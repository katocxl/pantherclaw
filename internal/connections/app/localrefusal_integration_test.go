// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR225_ALocalSecretRefusalReachesDetections (G0 M12 follow-up): a
// gateway's secret_in_payload refusal is audited as
// connection.secret_in_payload_refused, denied, with the gateway as actor
// and only the code, operation and run, which the detection feed reads; a
// report about another gateway's connection, or with another code, is
// refused and records nothing.
func TestHR225_ALocalSecretRefusalReachesDetections(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	ctx := context.Background()
	run := ids.NewV7()
	if err := e.svc.ReportLocalRefusal(ctx, e.org, other, c.ID, app.RefusalSecretInPayload, "payments.refund.create", run, app.RefusalDetail{}); !is(err, app.ErrNotFound) {
		t.Fatalf("another gateway's connection: %v", err)
	}
	if err := e.svc.ReportLocalRefusal(ctx, e.org, e.gateway, c.ID, "simulator_unverified", "payments.refund.create", run, app.RefusalDetail{}); !is(err, app.ErrRefusalCode) {
		t.Fatalf("another code: %v", err)
	}
	if err := e.svc.ReportLocalRefusal(ctx, e.org, e.gateway, c.ID, app.RefusalSecretInPayload, "payments.refund.create", run, app.RefusalDetail{}); err != nil {
		t.Fatal(err)
	}
	n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.connection.secret_in_payload_refused'
		AND actor_type = 'gateway' AND actor_id = $2
		AND convert_from(body, 'UTF8')::jsonb ->> 'outcome' = 'denied'
		AND convert_from(body, 'UTF8')::jsonb ->> 'reason_code' = 'SECRET_IN_PAYLOAD'
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $3
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'operation' = 'payments.refund.create'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'run_id' = $4`, e.org, e.gateway.String(), c.ID.String(), run.String())
	if n != 1 {
		t.Fatalf("%d audit events, want 1", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.connection.secret_in_payload_refused'`, e.org); n != 1 {
		t.Fatalf("the refused reports recorded %d events", n-1)
	}
	// The details carry nothing but the machine metadata.
	var keys string
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT string_agg(k, ',' ORDER BY k) FROM pc.ledger_entries,
			jsonb_object_keys(convert_from(body, 'UTF8')::jsonb -> 'details') k
			WHERE org_id = $1 AND kind = 'audit.connection.secret_in_payload_refused'`, e.org).Scan(&keys)
	}); err != nil {
		t.Fatal(err)
	}
	if keys != "code,operation,run_id" || strings.Contains(keys, "payload") {
		t.Fatalf("details %q", keys)
	}
}
