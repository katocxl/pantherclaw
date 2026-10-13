// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR160_MovingAConnectionDisablesItsOldGatewaysProvider (#299 review
// follow-up): when a connection moves to another gateway, the fact
// provider bound to the gateway it left is disabled in the same change,
// with its declarations and an audit event, so its facts stop counting and
// the new gateway can be registered at once; a provider of another
// connection is untouched.
func TestHR160_MovingAConnectionDisablesItsOldGatewaysProvider(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "github")
	untouched := e.payments(t, "other")
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", e.org, other)
	prov, keep := ids.NewV7(), ids.NewV7()
	for p, conn := range map[ids.UUID]ids.UUID{prov: c.ID, keep: untouched.ID} {
		fact := map[ids.UUID]string{prov: "github.pull.head", keep: "github.pull.people"}[p]
		e.exec(t, `INSERT INTO pc.fact_providers (org_id, id, name, gateway_id, connection_id, created_by)
			VALUES ($1, $2, $3, $4, $5, 'test')`, e.org, p, "github_"+p.String()[24:], e.gateway, conn)
		e.exec(t, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
			VALUES ($1, $2, $3, 'identifier', 'github.pull_request', 60)`, e.org, p, fact)
	}
	if _, err := e.svc.Update(e.admin, app.UpdateInput{ID: c.ID, Revision: c.Revision, Gateway: &other}); err != nil {
		t.Fatal(err)
	}
	state := func(p ids.UUID) int64 {
		return e.int64(t, `SELECT count(*) FROM pc.fact_providers f JOIN pc.fact_declarations d ON d.org_id = f.org_id AND d.provider_id = f.id
			WHERE f.org_id = $1 AND f.id = $2 AND f.state = 'ACTIVE' AND d.active`, e.org, p)
	}
	if state(prov) != 0 || state(keep) != 1 {
		t.Fatalf("after the move: the old provider %d active, the other connection's %d", state(prov), state(keep))
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.facts.provider_disabled'
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $2
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'reason' = 'connection_moved'`, e.org, prov.String()); n != 1 {
		t.Fatalf("%d audit events", n)
	}
	// The new gateway can be its provider now: the one active provider per
	// connection is free.
	e.exec(t, `INSERT INTO pc.fact_providers (org_id, id, name, gateway_id, connection_id, created_by)
		VALUES ($1, $2, 'github_new', $3, $4, 'test')`, e.org, ids.NewV7(), other, c.ID)
}
