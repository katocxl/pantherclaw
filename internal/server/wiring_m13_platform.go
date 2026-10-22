// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"connectrpc.com/connect/v2"
	"github.com/jackc/pgx/v5"
	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// The M13 platform stream's wiring (G0 M13 D3–D7, D26).

// publicCertReloader reads the public listener's certificate files, when
// configured, through a reloader (G0 M13 D4, HR-371); nil without TLS.
func publicCertReloader(cfg *Config, log *slog.Logger) (*httpx.CertReloader, error) {
	if cfg.HTTP.TLSCertFile == "" {
		return nil, nil
	}
	r, err := httpx.NewCertReloader(cfg.HTTP.TLSCertFile, cfg.HTTP.TLSKeyFile, log)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	return r, nil
}

// serveCertReloads polls the certificate files until ctx ends.
func serveCertReloads(ctx context.Context, g *errgroup.Group, certs *httpx.CertReloader) {
	if certs == nil {
		return
	}
	g.Go(func() error {
		certs.Run(ctx, httpx.CertReloadInterval)
		return nil
	})
}

// MaintenanceConfig is the operator's maintenance hold (G0 M13 D26,
// HR-379): while Hold is on, no decision is made from any path; people,
// service accounts and the operator commands keep working, so state can be
// inspected and revocations re-applied after a restore. Allowed in every
// deployment: it only ever refuses.
type MaintenanceConfig struct {
	Hold bool `json:"hold" env:"PC_MAINTENANCE_HOLD"`
}

// errMaintenanceHold is what every held path answers (UNAVAILABLE).
var errMaintenanceHold = authority.ErrMaintenanceHold

// heldOnAPI reports the API-listener procedures the hold refuses: the
// workload data plane and the Authority's decision procedures (which the
// API listener refuses anyway, HR-181).
func heldOnAPI(procedure string) bool {
	p := string(procedurePermissions[procedure])
	return strings.HasPrefix(p, "workload.") || p == "gateway.authorize" || p == "gateway.dispatch"
}

// heldOnGatewayListener refuses every gateway procedure: Authorize,
// dispatch, the containment stream, configuration and reports. Gateways
// fail closed, and their hook, SDK and MCP faces with them.
func heldOnGatewayListener(string) bool { return true }

// holdAuthenticator refuses held procedures before authentication while
// the hold is on.
func holdAuthenticator(held bool, refuse func(procedure string) bool, next rpc.Authenticator) rpc.Authenticator {
	if !held {
		return next
	}
	return func(ctx context.Context, info *connect.CallInfo, spec connect.Spec) (context.Context, error) {
		if refuse(spec.Procedure) {
			return nil, errMaintenanceHold
		}
		return next(ctx, info, spec)
	}
}

// heldHTTPPath reports the API-listener HTTP routes outside Connect that
// the hold refuses: a workload's wait stream and the AuthZEN decisions.
func heldHTTPPath(path string) bool {
	return strings.HasPrefix(path, workloadrpc.WaitPath) || path == authzenEvaluationPath || path == authzenEvaluationsPath
}

// holdHTTP answers held routes with 503 MAINTENANCE_HOLD while held.
func holdHTTP(held bool, refuse func(path string) bool, next http.Handler) http.Handler {
	if !held {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse(r.URL.Path) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"MAINTENANCE_HOLD"}` + "\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Maintenance hold audit events, in the platform org's ledger.
const (
	holdOnEvent  = "platform.maintenance_hold_on"
	holdOffEvent = "platform.maintenance_hold_off"
)

// auditMaintenanceHold records platform.maintenance_hold_on at every start
// with the hold, and platform.maintenance_hold_off at the first start
// without it after one with it.
func auditMaintenanceHold(ctx context.Context, pool *db.Pool, held bool, log *slog.Logger) error {
	err := pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		var last string
		err := tx.QueryRow(ctx, `SELECT kind FROM pc.ledger_entries WHERE org_id = $1 AND kind = ANY($2)
			ORDER BY occurred_at DESC, id DESC LIMIT 1`, ids.PlatformOrg,
			[]string{"audit." + holdOnEvent, "audit." + holdOffEvent}).Scan(&last)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var name string
		switch {
		case held:
			name = holdOnEvent
		case last == "audit."+holdOnEvent:
			name = holdOffEvent
		default:
			return nil
		}
		_, err = audit.Record(ctx, tx, audit.Event{Name: name, Actor: startupActor, Outcome: audit.Success})
		return err
	})
	if err != nil {
		return fmt.Errorf("server: audit the maintenance hold: %w", err)
	}
	if held {
		log.WarnContext(ctx, "server.maintenance_hold", slog.String("note",
			"no decision is made from any path; gateways fail closed; restart without maintenance.hold to resume"))
	}
	return nil
}
