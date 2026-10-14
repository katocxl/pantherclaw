// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR203_ATokenLeftValidIsAudited (#261 review follow-up, ADR-0021
// item 6, R-18): a gateway's report that a fact read's, verification
// read's or scan's token could not be revoked is audited as
// credential.revoke_failed with the gateway as actor, what the token was
// for, its repository and expiry; a report about another gateway's
// connection is refused and records nothing.
func TestHR203_ATokenLeftValidIsAudited(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "github")
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	ctx := context.Background()
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := e.svc.ReportRevocationFailure(ctx, e.org, other, c.ID, "facts", 7, "acme/payments", expires); !is(err, app.ErrNotFound) {
		t.Fatalf("another gateway's connection: %v", err)
	}
	for _, purpose := range []string{"facts", "verification", "org_scan"} {
		if err := e.svc.ReportRevocationFailure(ctx, e.org, e.gateway, c.ID, purpose, 7, "acme/payments", expires); err != nil {
			t.Fatalf("%s: %v", purpose, err)
		}
	}
	n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.credential.revoke_failed'
		AND actor_type = 'gateway' AND actor_id = $2
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $3
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'repository' = 'acme/payments'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'installation' = '7'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'expires_at' = $4`, e.org, e.gateway.String(), c.ID.String(), expires.Format(time.RFC3339))
	if n != 3 {
		t.Fatalf("%d audit events, want one per purpose", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.credential.revoke_failed'
		AND actor_type = 'gateway' AND actor_id = $2`, e.org, other.String()); n != 0 {
		t.Fatalf("the refused report recorded %d events", n)
	}
}
