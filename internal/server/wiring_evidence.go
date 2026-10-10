// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/adapters/evidencerpc"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// mountEvidenceKeys serves evidence-keys.json and revoked-keys.json
// (PAP-1 §11, G0 M7): public, from the keystore, without private material.
func mountEvidenceKeys(mux *http.ServeMux, d apiDeps) {
	pool := d.pool
	keydocs.New(func(ctx context.Context, ps []keys.Purpose) ([]keystore.PublishedKey, error) {
		return keystore.PublishedKeys(ctx, pool, ps)
	}, d.publicURL, d.logOrigin, clock.System{}, d.log).Mount(mux)
}

// registerEvidenceWorkers adds the checkpoint and daily verification jobs
// (G0 M7 design decision 8, HR-194) and returns their schedules.
func registerEvidenceWorkers(reg *jobs.Registry, cfg *Config, pool *db.Pool, keyReg *keys.Registry,
	notify checkpoints.Notifier, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	svc := &checkpoints.Service{
		Pool: pool, Keys: keyReg, LogOrigin: cfg.logOrigin(), Cosign: cfg.Evidence.MLDSACosign, Notify: notify, Log: log,
	}
	if err := checkpoints.Register(reg, svc); err != nil {
		return nil, err
	}
	return checkpoints.PeriodicJobs(cfg.checkpointInterval()), nil
}

// registerEvidence serves EvidenceService on the public API.
func registerEvidence(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterEvidenceServiceHandler(rs, evidencerpc.New(evapp.New(d.pool, d.logOrigin)))
}
