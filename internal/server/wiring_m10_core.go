// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"sync"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/reflex/adapters/reflexrpc"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// reflexCore is the M10 core wiring shared by the API and the worker (G0
// M10 D1, D9–D18): the verified built-in pack, the Raiser with its
// suppression, incident and notification hooks, and the FailureSink. Other
// M10 streams take their Raiser and FailureSink from here.
type reflexCore struct {
	env      *celenv.Env
	pack     *pack.Pack
	packErr  error
	hooks    *reflexapp.Hooks
	raiser   *alerts.Raiser
	failures *failures.Sink
}

var reflexCores = struct {
	sync.Mutex
	by map[*db.Pool]*reflexCore
}{by: map[*db.Pool]*reflexCore{}}

// newReflexCore loads and checks the built-in pack once per pool (D12): a
// mismatch keeps detections off and the engine raises an owned failure;
// the server still serves decisions, since detection is never on the
// decision path.
func newReflexCore(pool *db.Pool, limits celenv.Limits, bill *billing.Service, notify *napp.Service, log *slog.Logger) *reflexCore {
	reflexCores.Lock()
	defer reflexCores.Unlock()
	if c, ok := reflexCores.by[pool]; ok {
		return c
	}
	c := &reflexCore{failures: &failures.Sink{}, hooks: &reflexapp.Hooks{}}
	c.env, c.packErr = engine.NewEnv(limits)
	if c.packErr == nil {
		c.pack, c.packErr = pack.Load(c.env)
	}
	if c.packErr != nil && log != nil {
		log.Error("detection.pack_integrity_failed", slog.String("error", c.packErr.Error()))
	}
	if bill != nil {
		c.hooks.Ents = bill
	}
	if notify != nil {
		c.hooks.Notify = notify
	}
	c.raiser = c.hooks.Raiser()
	reflexCores.by[pool] = c
	return c
}

func (c *reflexCore) builtin() ([]*engine.Compiled, string) {
	if c.pack == nil {
		return nil, ""
	}
	return c.pack.Rules, c.pack.Version
}

// registerReflexCore serves IncidentService and DetectionService.
func registerReflexCore(rs *connect.Server, d apiDeps) {
	var notify *napp.Service
	if d.m5 != nil {
		notify = d.m5.notifications
	}
	c := newReflexCore(d.pool, d.cel, d.billing, notify, d.log)
	rules, version := c.builtin()
	det := &reflexapp.Detections{Pool: d.pool, Builtin: rules, PackVersion: version, PackErr: c.packErr, Env: c.env}
	if d.billing != nil {
		det.Ents = d.billing
	}
	pantherclawv1connect.RegisterIncidentServiceHandler(rs, reflexrpc.NewIncidents(&reflexapp.Incidents{Pool: d.pool, Hooks: c.hooks}))
	pantherclawv1connect.RegisterDetectionServiceHandler(rs, reflexrpc.NewDetections(det))
}

// registerReflexCoreJobs adds the detection engine (every 5 s per org) and
// the daily digest, and returns their schedules.
func registerReflexCoreJobs(reg *jobs.Registry, pool *db.Pool, limits celenv.Limits, bill *billing.Service, notify *napp.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	c := newReflexCore(pool, limits, bill, notify, log)
	rules, version := c.builtin()
	e := &engine.Engine{
		Pool: pool, Builtin: rules, PackVersion: version, PackErr: c.packErr, Env: c.env, Raiser: c.raiser, Sink: c.failures,
		Log: log,
	}
	d := &reflexapp.Digests{Pool: pool, Sink: c.failures}
	if bill != nil {
		e.Ents, d.Ents = bill, bill
	}
	if notify != nil {
		d.Notify = notify
	}
	periodic, err := engine.Register(reg, e)
	if err != nil {
		return nil, err
	}
	digest, err := reflexapp.RegisterDigest(reg, d)
	if err != nil {
		return nil, err
	}
	return append(periodic, digest...), nil
}
