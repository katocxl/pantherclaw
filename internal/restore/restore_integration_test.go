// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package restore

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func seedReplay(t *testing.T, d *dbtest.DB, org ids.OrgID, user, sa, key, session ids.UUID) {
	t.Helper()
	d.AdminExec(t, `INSERT INTO pc.orgs(id,name) VALUES($1,'restore-test')`, org)
	d.AdminExec(t, `INSERT INTO pc.users(org_id,id,issuer,subject) VALUES($1,$2,'https://example.test','subject')`, org, user)
	d.AdminExec(t, `INSERT INTO pc.service_accounts(org_id,id,name,created_by) VALUES($1,$2,'restore-test','system:test')`, org, sa)
	d.AdminExec(t, `INSERT INTO pc.api_keys(org_id,id,service_account_id,name,secret_hash,hint,scopes,created_by,expires_at) VALUES($1,$2,$3,'restore-test',decode(repeat('ab',32),'hex'),'test',ARRAY['agent.read'],'system:test',now()+interval '1 day')`, org, key, sa)
	d.AdminExec(t, `INSERT INTO pc.sessions(org_id,id,user_id,secret_hash,provider,roles_digest,expires_at) VALUES($1,$2,$3,decode(repeat('cd',32),'hex'),'test',decode(repeat('ef',32),'hex'),now()+interval '1 hour')`, org, session, user)
}

// TestHR384_TighteningIsTenantScopedIdempotentAndAudited uses identical
// object ids in two tenants and runs as pc_app, so a forgotten tenant
// filter or a non-idempotent transition cannot hide behind a superuser.
func TestHR384_TighteningIsTenantScopedIdempotentAndAudited(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	user, sa, key, session := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	seedReplay(t, d, org, user, sa, key, session)
	seedReplay(t, d, other, user, sa, key, session)
	var entries []Event
	for i, target := range []struct {
		kind, typ string
		id        ids.UUID
	}{{"access.user_disabled", "user", user}, {"access.service_account_disabled", "service_account", sa}, {"access.api_key_revoked", "api_key", key}, {"authn.session_ended", "browser_session", session}} {
		e := sample()
		e.Org = org
		e.LedgerSeq = int64(i + 1)
		e.Kind = target.kind
		e.Object = securityevent.Object{Type: target.typ, ID: target.id.String()}
		entries = append(entries, e)
	}
	loosen := sample()
	loosen.Org = org
	loosen.LedgerSeq = 5
	loosen.Kind = "access.user_enabled"
	loosen.Direction = "loosen"
	loosen.Object = securityevent.Object{Type: "user", ID: user.String()}
	entries = append(entries, loosen)
	r := NewRegistry()
	operator := domain.Actor{Type: "operator", ID: "cli:test"}
	if err := r.Reapply(ctx, p, entries, false, operator); err == nil {
		t.Fatal("replay succeeded without hold")
	}
	for range 2 {
		if err := r.Reapply(ctx, p, entries, true, operator); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []struct {
		table    string
		id       ids.UUID
		expected string
	}{{"users", user, "DISABLED"}, {"service_accounts", sa, "DISABLED"}, {"api_keys", key, "REVOKED"}, {"sessions", session, "ENDED"}} {
		var state string
		d.AdminQueryRow(t, "SELECT state FROM pc."+target.table+" WHERE org_id=$1 AND id=$2", []any{org, target.id}, &state)
		if state != target.expected {
			t.Errorf("%s state=%s", target.table, state)
		}
		d.AdminQueryRow(t, "SELECT state FROM pc."+target.table+" WHERE org_id=$1 AND id=$2", []any{other, target.id}, &state)
		if state != "ACTIVE" {
			t.Errorf("changed other tenant's %s: %s", target.table, state)
		}
	}
	var audits int
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id=$1 AND kind='audit.restore.reapplied' AND actor_type='operator' AND convert_from(body,'UTF8')::jsonb->'details'->>'count'='4'`, []any{org}, &audits)
	if audits != 2 {
		t.Fatalf("audits=%d, want 2", audits)
	}
}

func TestT173_OrgReplayRollsBackWhenAnyHandlerFails(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	user := ids.NewV7()
	seedReplay(t, d, org, user, ids.NewV7(), ids.NewV7(), ids.NewV7())
	e := sample()
	e.Org = org
	e.Kind = "access.user_disabled"
	e.Object = securityevent.Object{Type: "user", ID: user.String()}
	second := sample()
	second.Org = org
	second.LedgerSeq = 4
	r := NewRegistry()
	r.handlers[second.Kind] = func(context.Context, db.TenantTx, Event) error { return errors.New("injected failure") }
	if err := r.Reapply(context.Background(), p, []Event{e, second}, true, domain.Actor{Type: "operator", ID: "cli:test"}); err == nil {
		t.Fatal("failed handler reported success")
	}
	var state string
	d.AdminQueryRow(t, `SELECT state FROM pc.users WHERE org_id=$1 AND id=$2`, []any{org, user}, &state)
	if state != "ACTIVE" {
		t.Fatal("earlier change committed before failed handler")
	}
	var n int
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id=$1 AND kind='audit.restore.reapplied'`, []any{org}, &n)
	if n != 0 {
		t.Fatal("failed replay claimed audit success")
	}
}

// Every SQL handler must run under the application role and treat absent
// post-backup objects as safe no-ops. This exercises the actual schema,
// grants and typed arguments even when the object has no restored row.
func TestHR384_ClosedHandlersExecuteAgainstRestoredSchema(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	d.AdminExec(t, `INSERT INTO pc.orgs(id,name) VALUES($1,'restore-handler')`, org)
	r := NewRegistry()
	seq := int64(0)
	for kind := range r.handlers {
		if kind == "response.contain" {
			continue
		} // requires a real subject, separately tested
		t.Run(kind, func(t *testing.T) {
			seq++
			e := sample()
			e.Org = org
			e.Kind = kind
			e.LedgerSeq = seq
			_, typ, _ := securityevent.Rule(kind)
			e.Object.Type = typ
			switch typ {
			case "org":
				e.Object.ID = org.String()
			case "session":
				e.Object.Type = "browser_session"
			case "sealed_credential":
				e.Object.ID = ids.NewV7().String() + "/1"
			case "package_signing_key":
				e.RevocationReason = "ROTATED"
			}
			if err := r.Reapply(context.Background(), p, []Event{e}, true, domain.Actor{Type: "operator", ID: "cli:test"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHR384_AgentHeldRevocationNeverFabricatesLocalMaterial(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org := ids.New[ids.Org]()
	d.AdminExec(t, `INSERT INTO pc.orgs(id,name) VALUES($1,'restore-agent-held')`, org)
	e := sample()
	e.Org = org
	e.Kind = "response.credential_revoked"
	e.Object = securityevent.Object{Type: "sealed_credential", ID: ids.NewV7().String() + "/0"}
	r := NewRegistry()
	for range 2 {
		if err := r.Reapply(context.Background(), p, []Event{e}, true, domain.Actor{Type: "operator", ID: "cli:test"}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.credentials WHERE org_id=$1`, []any{org}, &n)
	if n != 0 {
		t.Fatal("invented local credential")
	}
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id=$1 AND kind='audit.restore.reapplied' AND convert_from(body,'UTF8')::jsonb->'details'->>'no_local_material'='1' AND convert_from(body,'UTF8')::jsonb->'details'->>'local_material'='0'`, []any{org}, &n)
	if n != 2 {
		t.Fatalf("no-local-material audits=%d", n)
	}
}

func TestHR384_ContainmentReplayReplansWithoutFalseConfirmation(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	agent := ids.NewV7()
	d.AdminExec(t, `INSERT INTO pc.orgs(id,name) VALUES($1,'restore-containment')`, org)
	d.AdminExec(t, `INSERT INTO pc.agents(org_id,id,name,state,created_by) VALUES($1,$2,'uncovered','DISCOVERED','system:test')`, org, agent)
	e := sample()
	e.Org = org
	e.Kind = "response.contain"
	e.Object.Type = "containment_control"
	e.Containment = &securityevent.Containment{ActionID: ids.NewV7(), ControlID: mustID(t, e.Object.ID), ScopeType: "agent", ScopeID: agent.String(), Control: "DENY_ALL", Source: "PERSON"}
	r := NewRegistry()
	for range 2 {
		if err := r.Reapply(ctx, p, []Event{e}, true, domain.Actor{Type: "operator", ID: "cli:test"}); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.containment_controls WHERE org_id=$1 AND id=$2 AND control='DENY_ALL' AND lifted_at IS NULL`, []any{org, e.Containment.ControlID}, &n)
	if n != 1 {
		t.Fatalf("controls=%d", n)
	}
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.response_paths WHERE org_id=$1 AND action_id=$2 AND material AND status='UNRESOLVED'`, []any{org, e.Containment.ActionID}, &n)
	if n < 1 {
		t.Fatal("uncovered agent was not marked unresolved")
	}
	var state string
	d.AdminQueryRow(t, `SELECT status FROM pc.response_actions WHERE org_id=$1 AND id=$2`, []any{org, e.Containment.ActionID}, &state)
	if state == "CONFIRMED" {
		t.Fatal("restore fabricated enforcement confirmation")
	}
	// Conflicting metadata never silently replaces a restored control.
	changed := *e.Containment
	changed.Control = "HOLD_WRITES"
	e.Containment = &changed
	if err := r.Reapply(ctx, p, []Event{e}, true, domain.Actor{Type: "operator", ID: "cli:test"}); err == nil {
		t.Fatal("conflicting control accepted")
	}
}
