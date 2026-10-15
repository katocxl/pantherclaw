// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"log/slog"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/billing"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/pgsimulation"
	"github.com/katocxl/pantherclaw/internal/policy/simulation/simulationrpc"
)

// simulationVersions reads stored policy versions for simulations, in READ
// ONLY transactions (the replay engine's source).
func simulationVersions(pool *db.Pool) *pgauthority.ReplaySource {
	return &pgauthority.ReplaySource{Pool: pool, Definitions: &defspg.Store{Pool: pool}, FactStore: &factspg.Store{Pool: pool}}
}

// registerSimulation serves PolicySimulationService on the public API (G0
// M11.1 D15), as pc_app; a simulation's job is enqueued in the transaction
// that stores it and runs in the worker. Editions come from the licence;
// without one the server is Community and simulation is refused.
func registerSimulation(rs *connect.Server, d apiDeps) error {
	insert, err := jobs.NewClient(d.pool, nil, jobs.Config{Logger: d.log}) // insert-only: enqueue in the creating transaction
	if err != nil {
		return err
	}
	svc := &simulation.Service{
		Store: pgsimulation.Store{Pool: d.pool, Jobs: insert}, Versions: simulationVersions(d.pool),
		IsNotFound: func(err error) bool { return errors.Is(err, replay.ErrNotFound) },
	}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterPolicySimulationServiceHandler(rs, simulationrpc.New(svc))
	return nil
}

// registerSimulationJobs adds the simulation worker: the replay engine
// (read ports only, HR-232) reading each proposed version once, the store
// of the simulation's own rows, and the licence, checked at each step
// (D34).
func registerSimulationJobs(reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider, bill *billing.Service, log *slog.Logger) error {
	engine := replayEngine(pool, kp)
	versions := &simulation.VersionCache{Source: engine.Source}
	engine.Source = versions
	r := &simulation.Runner{
		Store: pgsimulation.Store{Pool: pool}, Replay: engine, Versions: versions,
	}
	if bill != nil {
		r.Editions = bill
	}
	return pgsimulation.Register(reg, r, log)
}
