// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Readiness (G0 M13 D3, D19, HR-370).

// Start-up refusals: the database schema does not match this binary.
var (
	errSchemaNewer = pcerr.New(pcerr.FailedPrecondition, "SCHEMA_NEWER",
		"the database schema is newer than this binary; run the newer release")
	errSchemaPending = pcerr.New(pcerr.FailedPrecondition, "SCHEMA_PENDING",
		"the database schema is older than this binary; run `pantherclaw-server migrate up` first")
)

// checkSchemaAtStart refuses to serve a newer schema, and a pending one
// outside development (where it only warns).
func checkSchemaAtStart(ctx context.Context, cfg *Config, pool *db.Pool, log *slog.Logger) error {
	st, err := pool.CheckSchema(ctx)
	if err != nil {
		return err
	}
	switch st {
	case db.SchemaNewer:
		return errSchemaNewer
	case db.SchemaPending:
		if cfg.deployment() == extension.DeploymentDevelopment {
			log.WarnContext(ctx, "server.schema_pending", slog.String("note", "development: serving a schema with pending migrations"))
			return nil
		}
		return errSchemaPending
	default:
		return nil
	}
}

// Worker heartbeat: the workers count as alive while their client runs and
// beat within workerHeartbeatMaxAge.
const (
	workerHeartbeatEvery  = 10 * time.Second
	workerHeartbeatMaxAge = 30 * time.Second
)

// workerHeartbeat records when the job workers last showed they run.
type workerHeartbeat struct {
	last atomic.Int64 // unix nanoseconds; 0 before the workers start
	now  func() time.Time
}

// newWorkerHeartbeat returns a heartbeat for the roles that run workers,
// nil for the others.
func newWorkerHeartbeat(role string) *workerHeartbeat {
	if role != RoleWorker && role != RoleAll {
		return nil
	}
	return &workerHeartbeat{now: time.Now}
}

func (h *workerHeartbeat) beat() { h.last.Store(h.now().UnixNano()) }

// alive reports a beat within workerHeartbeatMaxAge.
func (h *workerHeartbeat) alive() bool {
	last := h.last.Load()
	return last != 0 && h.now().Sub(time.Unix(0, last)) <= workerHeartbeatMaxAge
}

// serve beats while the started client runs; once it stops, the beats stop
// and readiness fails within workerHeartbeatMaxAge.
func (h *workerHeartbeat) serve(ctx context.Context, g *errgroup.Group, client *jobs.Client) {
	if h == nil {
		return
	}
	h.beat()
	g.Go(func() error {
		t := time.NewTicker(workerHeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-client.Stopped():
				return nil
			case <-t.C:
				h.beat()
			}
		}
	})
}

// Check results in the /readyz body: fixed words, never versions or errors.
const (
	checkOK      = "ok"
	checkFailed  = "fail"
	checkSkipped = "skip"
)

type readyBody struct {
	Ready  bool        `json:"ready"`
	Checks readyChecks `json:"checks"`
}

type readyChecks struct {
	DB      string `json:"db"`
	Schema  string `json:"schema"`
	Workers string `json:"workers"`
}

// readiness serves /readyz: 200 only when the database answers, its schema
// is this binary's, and (role all) the workers beat; 503 otherwise.
type readiness struct {
	pool    *db.Pool
	workers *workerHeartbeat
	log     *slog.Logger
}

func (rd readiness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	c := readyChecks{DB: checkFailed, Schema: checkFailed, Workers: checkSkipped}
	err := rd.pool.InGlobalTx(ctx, db.GlobalHealth, func(ctx context.Context, tx db.GlobalTx) error {
		var one int
		return tx.QueryRow(ctx, "SELECT 1").Scan(&one)
	}, db.ReadOnly())
	if err != nil {
		rd.log.WarnContext(ctx, "server.not_ready", slog.String("check", "db"), pclog.Err(err))
	} else {
		c.DB = checkOK
		switch st, err := rd.pool.CheckSchema(ctx); {
		case err != nil:
			rd.log.WarnContext(ctx, "server.not_ready", slog.String("check", "schema"), pclog.Err(err))
		case st != db.SchemaCurrent:
			rd.log.WarnContext(ctx, "server.not_ready", slog.String("check", "schema"), slog.Bool("newer", st == db.SchemaNewer))
		default:
			c.Schema = checkOK
		}
	}
	if rd.workers != nil {
		c.Workers = checkOK
		if !rd.workers.alive() {
			c.Workers = checkFailed
			rd.log.WarnContext(ctx, "server.not_ready", slog.String("check", "workers"))
		}
	}
	body := readyBody{Ready: c.DB == checkOK && c.Schema == checkOK && c.Workers != checkFailed, Checks: c}
	w.Header().Set("Content-Type", "application/json")
	if !body.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(body)
}
