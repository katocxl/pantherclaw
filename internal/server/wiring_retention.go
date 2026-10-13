// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/evidence/adapters/evidenceadminrpc"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// registerEvidenceAdmin serves EvidenceAdminService on the public API (G0
// M7 design decisions 9 and 10): retention policies, legal holds, capture
// profiles and the audited read of a capture, as pc_app.
func registerEvidenceAdmin(rs *connect.Server, d apiDeps) {
	svc := &retention.Service{Pool: d.pool}
	cs := d.captures.service(d.pool)
	if d.m5 != nil && d.m5.notifications != nil {
		svc.Notify, cs.Notify = d.m5.notifications, d.m5.notifications
	}
	pantherclawv1connect.RegisterEvidenceAdminServiceHandler(rs, evidenceadminrpc.New(svc, cs))
}

// retentionPoolConns bounds the retention role's pool: one job per org at a
// time, a few orgs in parallel.
const retentionPoolConns = 2

// registerRetention adds the retention job (HR-198) and returns its
// schedule and a function that closes its pool. The pool of the
// pc_retention role is opened here, for the worker only, and used by
// nothing but the job. Without database.retention_password_file nothing is
// removed and every run records ROLE_UNAVAILABLE.
func registerRetention(ctx context.Context, reg *jobs.Registry, cfg *Config, app *db.Pool, log *slog.Logger) ([]*river.PeriodicJob, func(), error) {
	r := &retention.Remover{App: app, Log: log}
	closePool := func() {}
	if cfg.DB.RetentionPasswordFile == "" {
		log.WarnContext(ctx, "evidence.retention_disabled", slog.String("reason", "database.retention_password_file is not set"))
	} else {
		c, err := cfg.dbConfig(cfg.retentionUser(), cfg.DB.RetentionPasswordFile, retentionPoolConns)
		if err != nil {
			return nil, nil, err
		}
		pool, err := db.Open(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		r.Pool, closePool = pool, pool.Close
	}
	if err := retention.Register(reg, r); err != nil {
		closePool()
		return nil, nil, err
	}
	return retention.PeriodicJobs(), closePool, nil
}
