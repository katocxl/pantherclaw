// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

// holdAfterPromotion starts the server in the maintenance hold when the
// database was promoted without verified synchronous replication (G0 M19
// D202, D207, HR-496): commits may have been lost, so no decision is made
// until `keys bump-epochs --all --confirm` raises every epoch and
// acknowledges the new timeline, and the server is restarted. The hold is
// audited and served like the operator's own (HR-379).
func holdAfterPromotion(ctx context.Context, cfg *Config, pool *db.Pool, log *slog.Logger) error {
	p, err := pool.CheckPromotion(ctx, db.Replication(cfg.DB.Replication))
	if err != nil {
		return err
	}
	if p.Unverified {
		log.WarnContext(ctx, "server.replication_unverified", slog.String("note",
			"database.replication is sync, but the primary does not run synchronous_commit=remote_apply "+
				"with a synchronous standby; a promotion counts as asynchronous"))
	}
	if !p.Hold {
		return nil
	}
	log.WarnContext(ctx, "server.promotion_hold", slog.Int64("timeline", p.Timeline),
		slog.Int64("acknowledged", p.Acknowledged), slog.String("note",
			"the database was promoted without verified synchronous replication; run keys bump-epochs --all --confirm, then restart"))
	cfg.Maintenance.Hold = true
	telemetry.SetMaintenanceHold(true)
	return nil
}

// livez answers /livez: ok, unless the pool saw a promotion it could not
// accept (D213), so the orchestrator restarts the process into the
// start-up hold.
func livez(pool *db.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if pool.TimelineChanged() {
			http.Error(w, "database promoted; restart into the maintenance hold", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	}
}
