// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestIntAccessDetailNamesTheModesAndWhatTheyDisclose: a
// PantherClaw-held connection names the gateway as custodian, an expiry
// and an issuance source, and never a secret; a current
// closure adds the constrained runtime with its expiry; agent-held access
// is disclosed as such once the connection changes (which also ends the
// closure's hold); every disclosure ends with the short-expiry warning and
// lists the agent's routes that are not closed.
func TestIntAccessDetailNamesTheModesAndWhatTheyDisclose(t *testing.T) {
	f := newFixture(t)
	auditor := f.as(td.RoleAuditor)
	d, err := f.svc.GetAccessDetail(auditor, f.conn, nil)
	if err != nil || !slices.Equal(d.Modes, []string{app.ModePantherClawHeld}) || d.Custodian != "gateway" ||
		d.Gateway != f.gateway || d.Disclosures[len(d.Disclosures)-1] != app.ShortExpiryNote || d.Expiry == "" ||
		d.IssuedBy == "" || len(d.Agents) != 0 {
		t.Fatalf("PantherClaw-held: %+v (%v)", d, err)
	}
	if _, err := f.svc.GetAccessDetail(auditor, f.conn, &f.agent); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("an agent without coverage on the connection: %v", err)
	}
	// coverage.read alone does not show the connection's configuration.
	d, err = f.svc.GetAccessDetail(f.as(td.RoleAgentOwner), f.conn, nil)
	if err != nil || !d.Gateway.IsZero() || d.CredentialVersion != 0 || len(d.Audience) != 0 || d.IssuedAt != nil ||
		!strings.HasPrefix(d.IssuedBy, "withheld") {
		t.Fatalf("an agent owner without connection.read: %+v (%v)", d, err)
	}
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK',
		'gw', $6, 'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), f.conn)
	if _, err := f.record(t, f.closure(probes(false), f.dbNow(t))); err != nil {
		t.Fatal(err)
	}
	f.reassessOrg(t)
	d, err = f.svc.GetAccessDetail(auditor, f.conn, &f.agent)
	if err != nil || !slices.Equal(d.Modes, []string{app.ModePantherClawHeld, app.ModeConstrainedRuntime}) || d.Closure == nil ||
		len(d.Disclosures) != 3 || !slices.ContainsFunc(d.Residual, func(r app.SnapshotRoute) bool { return r.Kind == "target_side" }) ||
		d.ExpiresAt == nil || !slices.Equal(d.Agents, []ids.UUID{f.agent}) || len(d.Basis) != 2 {
		t.Fatalf("with a closure: %+v (%v)", d, err)
	}
	if slices.ContainsFunc(d.Residual, func(r app.SnapshotRoute) bool { return r.Kind == "host" }) {
		t.Fatalf("a route the current closure closed is residual: %+v", d.Residual)
	}
	// A change the snapshot did not see ends the closure's hold: what it
	// closed is residual again, before any reassessment.
	f.exec(t, `INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id) VALUES ($1, $2, 'gateway', $3, $4)`,
		f.org, ids.NewV7(), f.conn, f.agent)
	d, err = f.svc.GetAccessDetail(auditor, f.conn, &f.agent)
	if err != nil || d.Closure != nil || !slices.ContainsFunc(d.Residual, func(r app.SnapshotRoute) bool { return r.Kind == "host" }) {
		t.Fatalf("after a change the closure did not see: %+v (%v)", d, err)
	}
	f.exec(t, "UPDATE pc.connections SET access_mode = 'agent_held' WHERE id = $1", f.conn)
	d, err = f.svc.GetAccessDetail(auditor, f.conn, &f.agent)
	if err != nil || !slices.Equal(d.Modes, []string{app.ModeAgentHeld}) || d.Custodian != "agent" || d.Closure != nil {
		t.Fatalf("agent-held after the change: %+v (%v)", d, err)
	}
	if _, err := f.svc.GetAccessDetail(f.as(td.RoleViewer), f.conn, nil); err == nil {
		t.Fatal("a viewer read the access detail")
	}
}

// TestIntAccessDetailListsEachVerifiedRead: on target-enforced access the
// detail lists, per read of the scopes shown, its latest passing
// target-verifier test, and never a write's (founder decision N15).
func TestIntAccessDetailListsEachVerifiedRead(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'target_enforced' WHERE id = $1", f.conn)
	at := f.dbNow(t).Add(-time.Minute)
	f.svc.Verifier = &verifier{passed: map[string]time.Time{"payments.refund.get": at, "payments.refund.create": at}}
	for _, op := range []string{"payments.refund.get", "payments.refund.create"} {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7,
			'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	}
	f.reassessOrg(t)
	d, err := f.svc.GetAccessDetail(f.as(td.RoleAuditor), f.conn, &f.agent)
	if err != nil || !slices.Equal(d.Modes, []string{app.ModeTargetEnforced}) || len(d.Verified) != 1 ||
		d.Verified[0].Operation != "payments.refund.get" || !d.Verified[0].At.Equal(at) {
		t.Fatalf("verified reads: %+v (%v)", d.Verified, err)
	}
}
