// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	casesdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	casesstore "github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

type fixture struct {
	t      *testing.T
	p      *db.Pool
	org    ids.OrgID
	alice  ids.UUID
	conn   ids.UUID
	svc    *tsapp.Service
	config ids.UUID
	secret []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{t: t, p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), conn: ids.NewV7()}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	env := pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(f.p, kp), time.Minute, clock.System{}))
	f.svc = &tsapp.Service{Pool: f.p, Envelope: env, Editions: edition(billing.Business)}
	gw := ids.NewV7()
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'tickets')", f.org)
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.alice)
	f.exec("INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'gw', 'test')", f.org, gw)
	f.exec(`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
		VALUES ($1, $2, 'jira', 'http', $3, 'pc.jira', 'https://example.atlassian.net', 'none', 'test', 'test')`, f.org, f.conn, gw)
	cfg, secret, err := f.svc.CreateConfig(f.as(), f.conn, "SEC")
	if err != nil {
		t.Fatal(err)
	}
	f.config, f.secret = cfg.ID, secret
	return f
}

// as is alice, a person who manages connections, cases and incidents.
func (f *fixture) as() context.Context {
	org := td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.alice},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: org}, {Role: td.RoleSecurityAdmin, Scope: org}, {Role: td.RoleResponder, Scope: org}},
	}})
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// containedCase opens a case linked to SEC-7 with an active containment
// control on an agent, and returns the case and the control.
func (f *fixture) containedCase() (ids.UUID, ids.UUID) {
	f.t.Helper()
	var kase casesdomain.Case
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		kase, err = casesstore.Open(ctx, tx, casesdomain.NewCase{
			Title: "leaked token", Source: "manual", OpenedBy: casesdomain.Author{Type: "user", ID: f.alice.String()},
		})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.LinkCase(f.as(), kase.ID, f.config, "SEC-7"); err != nil {
		f.t.Fatal(err)
	}
	action, control, agent := ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.response_actions (org_id, id, kind, scope_type, scope_id, control, reason, case_id, actor, source, status)
		VALUES ($1, $2, 'CONTAIN', 'agent', $3, 'DENY_ALL', 'contain', $4, $5, 'PERSON', 'REQUESTED')`,
		f.org, action, agent.String(), kase.ID, "user:"+f.alice.String())
	f.exec(`INSERT INTO pc.containment_controls (org_id, id, action_id, scope_type, scope_id, control, reason, case_id, created_by)
		VALUES ($1, $2, $3, 'agent', $4, 'DENY_ALL', 'contain', $5, $6)`,
		f.org, control, action, agent.String(), kase.ID, "user:"+f.alice.String())
	return kase.ID, control
}

func (f *fixture) epoch() int {
	return f.count("SELECT coalesce((SELECT epoch FROM pc.org_containment WHERE org_id = $1), 0)::int", f.org)
}

func (f *fixture) deliver(delivery string, body []byte, secret []byte) (string, error) {
	return f.svc.Inbound(context.Background(), f.org, f.config, delivery, domain.SignJira(secret, body), body)
}

func statusEvent(at int64, status, category string) []byte {
	return fmt.Appendf(nil, `{"timestamp":%d,"webhookEvent":"jira:issue_updated",
		"issue":{"key":"SEC-7","fields":{"status":{"statusCategory":{"key":%q}}}},
		"changelog":{"items":[{"field":"status","fromString":"To Do","toString":%q}]}}`, at, category, status)
}

// TestHR527_TicketStatusNeverRestores: a Jira transition to Done on a
// synced case, a forged webhook and a replay all leave its containment
// active and the containment epoch unchanged; the Done is only noted, as
// an EXTERNAL entry and an audit record (HR-527, T-227).
//
// Covers: F545
func TestHR527_TicketStatusNeverRestores(t *testing.T) {
	f := newFixture(t)
	kase, control := f.containedCase()
	epoch := f.epoch()
	untouched := func(step string) {
		t.Helper()
		if n := f.count("SELECT count(*) FROM pc.containment_controls WHERE org_id = $1 AND id = $2 AND lifted_at IS NULL", f.org, control); n != 1 {
			t.Fatalf("%s: the containment control was lifted", step)
		}
		if e := f.epoch(); e != epoch {
			t.Fatalf("%s: the containment epoch moved from %d to %d", step, epoch, e)
		}
		if n := f.count("SELECT count(*) FROM pc.restoration_plans WHERE org_id = $1", f.org); n != 0 {
			t.Fatalf("%s: %d restoration plans", step, n)
		}
		if n := f.count("SELECT count(*) FROM pc.cases WHERE org_id = $1 AND id = $2 AND state = 'OPEN'", f.org, kase); n != 1 {
			t.Fatalf("%s: the case moved", step)
		}
	}
	done := statusEvent(1793361600000, "Done", "done")
	out, err := f.deliver("delivery-1", done, f.secret)
	if err != nil || out != tsapp.OutcomeNoted {
		t.Fatalf("Done: %q %v", out, err)
	}
	untouched("a transition to Done")
	if n := f.count(`SELECT count(*) FROM pc.case_entries WHERE org_id = $1 AND case_id = $2 AND kind = 'EXTERNAL'
		AND author_type = 'system' AND author_id = 'ticketsync' AND text LIKE '%never restores authority%'`, f.org, kase); n != 1 {
		t.Fatalf("the Done was not noted as an EXTERNAL entry: %d", n)
	}
	if n := f.count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.ticket.owned_field_ignored'", f.org); n != 1 {
		t.Fatalf("the Done was not audited: %d", n)
	}

	// A forged webhook: another key signs it.
	forged := statusEvent(1793361700000, "Done", "done")
	if _, err := f.deliver("delivery-2", forged, []byte("attacker-0123456789")); !errors.Is(err, tsapp.ErrSignature) {
		t.Fatalf("a forged webhook: %v", err)
	}
	untouched("a forged webhook")
	if n := f.count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.ticket.webhook_refused'", f.org); n != 1 {
		t.Fatalf("the forged webhook was not audited: %d", n)
	}

	// A replay: the same delivery again, and an old event under a new id.
	entries := f.count("SELECT count(*) FROM pc.case_entries WHERE org_id = $1 AND case_id = $2", f.org, kase)
	if out, err := f.deliver("delivery-1", done, f.secret); err != nil || out != "" {
		t.Fatalf("a replayed delivery: %q %v", out, err)
	}
	if out, err := f.deliver("delivery-3", done, f.secret); err != nil || out != tsapp.OutcomeStale {
		t.Fatalf("a replayed event: %q %v", out, err)
	}
	untouched("a replay")
	if n := f.count("SELECT count(*) FROM pc.case_entries WHERE org_id = $1 AND case_id = $2", f.org, kase); n != entries {
		t.Fatalf("a replay added %d entries", n-entries)
	}
}

// TestHR528_OwnedFieldChangesIgnoredAndRecorded: an inbound change to a
// PantherClaw-owned field is dropped, entered as EXTERNAL and audited;
// ticket-owned changes and comments are mirrored as notes; an incident
// gets notes and keeps its severity and state (HR-528).
//
// Covers: F545
func TestHR528_OwnedFieldChangesIgnoredAndRecorded(t *testing.T) {
	f := newFixture(t)
	kase, _ := f.containedCase()
	body := []byte(`{"timestamp":1793361600000,"webhookEvent":"jira:issue_updated","issue":{"key":"SEC-7"},
		"changelog":{"items":[{"field":"Severity","toString":"Low"},{"field":"assignee","toString":"Bob"},
		{"field":"Containment","toString":"Lifted"}]}}`)
	if out, err := f.deliver("d-1", body, f.secret); err != nil || out != tsapp.OutcomeIgnored {
		t.Fatalf("owned changes: %q %v", out, err)
	}
	kinds := func(kind string) int {
		return f.count("SELECT count(*) FROM pc.case_entries WHERE org_id = $1 AND case_id = $2 AND kind = $3", f.org, kase, kind)
	}
	if kinds("EXTERNAL") != 2 || kinds("NOTE") != 1 {
		t.Fatalf("entries: %d EXTERNAL, %d NOTE", kinds("EXTERNAL"), kinds("NOTE"))
	}
	if n := f.count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.ticket.owned_field_ignored'", f.org); n != 2 {
		t.Fatalf("%d owned_field_ignored audits", n)
	}
	comment := []byte(`{"timestamp":1793361700000,"webhookEvent":"comment_created","issue":{"key":"SEC-7"},
		"comment":{"id":"1","author":{"displayName":"Bob"},"body":"rotated the key"}}`)
	if out, err := f.deliver("d-2", comment, f.secret); err != nil || out != tsapp.OutcomeApplied || kinds("NOTE") != 2 {
		t.Fatalf("a comment: %q %v, %d notes", out, err, kinds("NOTE"))
	}

	// An incident keeps its severity and state.
	inc := ids.NewV7()
	f.exec("INSERT INTO pc.incidents (org_id, id, title, severity, opened_by) VALUES ($1, $2, 'incident', 'HIGH', 'user:x')", f.org, inc)
	if _, err := f.svc.LinkIncident(f.as(), inc, f.config, "SEC-8"); err != nil {
		t.Fatal(err)
	}
	sev := []byte(`{"timestamp":1793361600000,"webhookEvent":"jira:issue_updated","issue":{"key":"SEC-8"},
		"changelog":{"items":[{"field":"Severity","toString":"Low"},{"field":"resolution","toString":"Fixed"}]}}`)
	if out, err := f.deliver("d-3", sev, f.secret); err != nil || out != tsapp.OutcomeIgnored {
		t.Fatalf("incident: %q %v", out, err)
	}
	if n := f.count("SELECT count(*) FROM pc.incidents WHERE org_id = $1 AND id = $2 AND severity = 'HIGH' AND state = 'OPEN'", f.org, inc); n != 1 {
		t.Fatal("the incident changed")
	}
	if n := f.count("SELECT count(*) FROM pc.incident_events WHERE org_id = $1 AND incident_id = $2 AND kind = 'NOTE' AND actor_id = 'ticketsync'", f.org, inc); n != 2 {
		t.Fatalf("%d incident notes", n)
	}
}

// TestTicketSync_Edition: below Business there is no ticket sync, inbound
// or configured (F545).
//
// Covers: F545
func TestTicketSync_Edition(t *testing.T) {
	f := newFixture(t)
	f.svc.Editions = edition(billing.Team)
	if _, _, err := f.svc.CreateConfig(f.as(), f.conn, "OPS"); !errors.Is(err, tsapp.ErrEdition) {
		t.Fatalf("create below Business: %v", err)
	}
	if _, err := f.deliver("d-1", statusEvent(1, "Done", "done"), f.secret); !errors.Is(err, tsapp.ErrEdition) {
		t.Fatalf("inbound below Business: %v", err)
	}
}

// TestTicketSync_LinkChecks: a key outside the configuration's project, a
// second link of the same case, and a caller without case.manage are
// refused.
func TestTicketSync_LinkChecks(t *testing.T) {
	f := newFixture(t)
	kase, _ := f.containedCase()
	if _, err := f.svc.LinkCase(f.as(), kase, f.config, "OPS-1"); !errors.Is(err, tsapp.ErrInvalid) {
		t.Fatalf("another project's key: %v", err)
	}
	if _, err := f.svc.LinkCase(f.as(), kase, f.config, "SEC-9"); !errors.Is(err, tsapp.ErrLinked) {
		t.Fatalf("a second link: %v", err)
	}
	viewer := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.alice},
		Bindings: []td.Binding{{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
	}})
	if _, err := f.svc.LinkCase(viewer, kase, f.config, "SEC-10"); err == nil {
		t.Fatal("a viewer linked a case")
	}
}
