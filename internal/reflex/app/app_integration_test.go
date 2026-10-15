// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type ents struct{ e billing.Edition }

func (x ents) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: x.e}, nil
}

type notifier struct{ sent []napp.Message }

func (n *notifier) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

func (n *notifier) count(typ string) int {
	c := 0
	for _, m := range n.sent {
		if m.Type == typ {
			c++
		}
	}
	return c
}

type fixture struct {
	p          *db.Pool
	org        ids.OrgID
	alice      ids.UUID
	agentA     ids.UUID
	agentB     ids.UUID
	n          *notifier
	hooks      *reflexapp.Hooks
	raiser     *alerts.Raiser
	svc        *reflexapp.Incidents
	teamA, env ids.UUID
}

func newFixture(t *testing.T, edition billing.Edition) *fixture {
	t.Helper()
	d := dbtest.New(t)
	f := &fixture{
		p: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), agentA: ids.NewV7(), agentB: ids.NewV7(), n: &notifier{},
	}
	f.hooks = &reflexapp.Hooks{Ents: ents{edition}, Notify: f.n}
	f.raiser = f.hooks.Raiser()
	f.svc = &reflexapp.Incidents{Pool: f.p, Hooks: f.hooks}
	f.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'reflex')", f.org)
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.alice)
	for _, a := range []ids.UUID{f.agentA, f.agentB} {
		f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'test')",
			f.org, a, "agent-"+a.String()[:8])
	}
	return f
}

func (f *fixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (f *fixture) as(roles ...td.RoleName) context.Context {
	bs := make([]td.Binding, 0, len(roles))
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.alice}, Bindings: bs},
		Credential: tenancy.CredAccessToken,
	})
}

func (f *fixture) signal(rule string, sev reflexdomain.Severity, att reflexdomain.Attention, agent ids.UUID) reflexdomain.Signal {
	return reflexdomain.Signal{
		Org: f.org, Source: reflexdomain.SourceDetection, RuleID: rule, RuleVersion: "1", RuleDigest: strings.Repeat("ab", 32),
		PackVersion: "1", Title: "Burst of denied actions in a run", Severity: sev, Attention: att, Basis: reflexdomain.BasisInferred,
		Subjects:   []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: agent.String()}, {Type: reflexdomain.SubjectRun, ID: "r1"}},
		OccurredAt: time.Now(), GroupKey: "run:r1",
	}
}

func (f *fixture) raise(t *testing.T, s reflexdomain.Signal) alerts.Raised {
	t.Helper()
	var r alerts.Raised
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		r, err = f.raiser.RaiseTx(ctx, tx, s)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

const rule = "pc.probing.denial_burst"

// TestHR242_SuppressionNeedsScopeReasonAndExpiry: a suppression needs a
// rule, a reason and an expiry within 30 days, needs Team and a person
// holding incident.manage.
func TestHR242_SuppressionNeedsScopeReasonAndExpiry(t *testing.T) {
	f := newFixture(t, billing.Team)
	ctx := f.as(td.RoleSecurityAdmin)
	for name, r := range map[string]reflexapp.SuppressionRequest{
		"no reason":     {Rule: rule, MaxSeverity: reflexdomain.SeverityMedium, ExpiresIn: time.Hour},
		"no rule":       {MaxSeverity: reflexdomain.SeverityMedium, Reason: "noisy", ExpiresIn: time.Hour},
		"too long":      {Rule: rule, MaxSeverity: reflexdomain.SeverityMedium, Reason: "noisy", ExpiresIn: 31 * 24 * time.Hour},
		"no expiry":     {Rule: rule, MaxSeverity: reflexdomain.SeverityMedium, Reason: "noisy"},
		"bad severity":  {Rule: rule, MaxSeverity: "LOUD", Reason: "noisy", ExpiresIn: time.Hour},
		"invalid scope": {Rule: rule, MaxSeverity: reflexdomain.SeverityLow, Reason: "noisy", ExpiresIn: time.Hour, Subjects: []reflexdomain.Subject{{Type: "planet", ID: "x"}}},
	} {
		if _, err := f.svc.CreateSuppression(ctx, r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := reflexapp.SuppressionRequest{Rule: rule, MaxSeverity: reflexdomain.SeverityMedium, Reason: "noisy", ExpiresIn: time.Hour}
	if _, err := f.svc.CreateSuppression(f.as(td.RoleViewer), ok); err == nil {
		t.Error("a viewer suppressed")
	}
	community := newFixture(t, billing.Community)
	if _, err := community.svc.CreateSuppression(community.as(td.RoleSecurityAdmin), ok); !errors.Is(err, reflexapp.ErrEdition) {
		t.Errorf("Community: %v, want EDITION_REQUIRED", err)
	}
	// The database refuses an expiry beyond 30 days whatever the caller says.
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.suppressions (org_id, id, rule_id, max_severity, reason, created_by, expires_at)
			VALUES ($1, $2, $3, 'LOW', 'x', $4, now() + interval '31 days')`, f.org, ids.NewV7(), rule, f.alice)
		return err
	})
	if err == nil {
		t.Error("the database stored a 31-day suppression")
	}
}

// TestT106_SuppressionCannotHideARealIncident: suppressed alerts stay
// listable and never notify or page; a higher severity, a subject outside
// the scope or a failed containment bypasses the suppression and reopens
// the alert, and the bypassed subject stays out of it (HR-242, HR-243).
func TestT106_SuppressionCannotHideARealIncident(t *testing.T) {
	f := newFixture(t, billing.Team)
	ctx := f.as(td.RoleSecurityAdmin)
	sup, err := f.svc.CreateSuppression(ctx, reflexapp.SuppressionRequest{
		Rule: rule, MaxSeverity: reflexdomain.SeverityMedium, Reason: "known noisy runner", ExpiresIn: 24 * time.Hour,
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agentA.String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	quiet := f.raise(t, f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionPage, f.agentA))
	if quiet.State != alerts.StateSuppressed || quiet.Incident != nil {
		t.Fatalf("in scope: %+v", quiet)
	}
	if len(f.n.sent) != 0 {
		t.Fatalf("a suppressed alert notified: %v", f.n.sent)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.incidents WHERE org_id = $1", f.org); n != 0 {
		t.Fatal("a suppressed PAGE opened an incident")
	}
	listed, err := f.svc.ListAlerts(ctx, reflexapp.AlertFilter{States: []string{alerts.StateSuppressed}}, 50, "")
	if err != nil || len(listed.Items) != 1 {
		t.Fatalf("suppressed alerts are not listable: %v %d", err, len(listed.Items))
	}
	// Higher severity: bypasses, reopens and pages.
	loud := f.raise(t, f.signal(rule, reflexdomain.SeverityCritical, reflexdomain.AttentionPage, f.agentA))
	if loud.Alert != quiet.Alert || loud.State != alerts.StateOpen || !loud.Reopened {
		t.Fatalf("severity bypass: %+v", loud)
	}
	if f.n.count(reflexdomain.NotifyPage) != 1 {
		t.Errorf("the bypass did not page: %v", f.n.sent)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND id = $2 AND severity = 'CRITICAL' AND attention = 'PAGE'`,
		f.org, loud.Alert); n != 1 {
		t.Error("the bypass did not raise the stored severity")
	}
	if f.count(t, `SELECT count(*) FROM pc.suppression_breaks WHERE org_id = $1 AND suppression_id = $2
		AND reason = 'SEVERITY_ABOVE_MAX'`, f.org, sup.ID) == 0 {
		t.Error("no break recorded")
	}
	// The bypassed subject stays out of the suppression.
	f.exec(t, "UPDATE pc.alerts SET state = 'RESOLVED' WHERE org_id = $1", f.org)
	again := f.raise(t, f.signal(rule, reflexdomain.SeverityLow, reflexdomain.AttentionAlert, f.agentA))
	if again.State != alerts.StateOpen {
		t.Errorf("a broken subject was suppressed again: %+v", again)
	}
	// A subject outside the scope bypasses it.
	outside := f.signal(rule, reflexdomain.SeverityLow, reflexdomain.AttentionAlert, f.agentB)
	outside.Subjects = append(outside.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: f.agentA.String()})
	outside.DedupeKey = "outside"
	if r := f.raise(t, outside); r.State != alerts.StateOpen {
		t.Errorf("subject outside the scope: %+v", r)
	}
	// Failed containment is never suppressible.
	g := newFixture(t, billing.Team)
	if _, err := g.svc.CreateSuppression(g.as(td.RoleSecurityAdmin), reflexapp.SuppressionRequest{
		Rule: "response.containment_failed", MaxSeverity: reflexdomain.SeverityCritical, Reason: "x", ExpiresIn: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	failed := g.signal("response.containment_failed", reflexdomain.SeverityHigh, reflexdomain.AttentionAlert, g.agentA)
	failed.Source = reflexdomain.SourceResponse
	if r := g.raise(t, failed); r.State != alerts.StateOpen {
		t.Errorf("failed containment was suppressed: %+v", r)
	}
	// Alert history is append-only.
	for _, sql := range []string{
		"UPDATE pc.suppression_breaks SET reason = 'x' WHERE org_id = $1", "DELETE FROM pc.suppression_breaks WHERE org_id = $1",
		"UPDATE pc.incident_events SET note = 'x' WHERE org_id = $1", "DELETE FROM pc.incident_events WHERE org_id = $1",
	} {
		err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, f.org)
			return err
		})
		if !db.IsPermissionDenied(err) {
			t.Errorf("%s: %v, want permission denied", sql, err)
		}
	}
}

// TestT106_TestSignalsNeverPage: a test PAGE signal is capped at ALERT,
// sends reflex.alert and opens no incident (F616).
func TestT106_TestSignalsNeverPage(t *testing.T) {
	f := newFixture(t, billing.Team)
	s := f.signal(rule, reflexdomain.SeverityCritical, reflexdomain.AttentionPage, f.agentA)
	s.Test = true
	r := f.raise(t, s)
	if r.Attention != reflexdomain.AttentionAlert || r.Incident != nil {
		t.Fatalf("%+v", r)
	}
	if f.n.count(reflexdomain.NotifyPage) != 0 || f.n.count(reflexdomain.NotifyAlert) != 1 {
		t.Errorf("notifications %v", f.n.sent)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.incidents WHERE org_id = $1", f.org); n != 0 {
		t.Error("a test signal opened an incident")
	}
}

// TestIncidentsGroupByEvidence: a PAGE opens an incident in every edition;
// with Team, a later ALERT of the same run attaches to it; the same rule on
// other subjects is listed as possibly related, never attached; closing an
// incident is a state change with an event.
func TestIncidentsGroupByEvidence(t *testing.T) {
	for _, edition := range []billing.Edition{billing.Community, billing.Team} {
		f := newFixture(t, edition)
		page := f.raise(t, f.signal("pc.integrity.action_tampered", reflexdomain.SeverityCritical, reflexdomain.AttentionPage, f.agentA))
		if page.Incident == nil {
			// Write reports the incident only on a repeat; read it back.
			if n := f.count(t, "SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND incident_id IS NOT NULL", f.org); n != 1 {
				t.Fatalf("%s: a PAGE opened no incident", edition)
			}
		}
		later := f.raise(t, f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA))
		attached := f.count(t, "SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND id = $2 AND incident_id IS NOT NULL", f.org, later.Alert)
		if want := map[billing.Edition]int{billing.Community: 0, billing.Team: 1}[edition]; attached != want {
			t.Errorf("%s: ALERT attached %d, want %d", edition, attached, want)
		}
		if edition == billing.Team && (f.n.count(reflexdomain.NotifyPage) != 1 || f.n.count(reflexdomain.NotifyIncident) != 1) {
			t.Errorf("Team notifications %v", f.n.sent)
		}
		// Pages and incidents notify in every edition; routine alerts only
		// with Team (D59 L13).
		if edition == billing.Community && (f.n.count(reflexdomain.NotifyPage) != 1 || f.n.count(reflexdomain.NotifyIncident) != 1 ||
			f.n.count(reflexdomain.NotifyAlert) != 0) {
			t.Errorf("Community notifications %v", f.n.sent)
		}
	}
	f := newFixture(t, billing.Team)
	a := f.raise(t, f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA))
	other := f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentB)
	other.GroupKey = "run:r2"
	other.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agentB.String()}}
	b := f.raise(t, other)
	ctx := f.as(td.RoleSecurityAdmin)
	inc, err := f.svc.PromoteAlert(ctx, a.Alert, "looks real")
	if err != nil {
		t.Fatal(err)
	}
	d, err := f.svc.GetAlert(ctx, a.Alert)
	if err != nil || len(d.Related) != 1 || d.Related[0].ID != b.Alert || d.Related[0].IncidentID != nil {
		t.Fatalf("possibly related: %v %+v", err, d.Related)
	}
	if _, err := f.svc.SetIncidentState(ctx, inc.ID, "RESOLVED", "done"); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.incident_events WHERE org_id = $1 AND incident_id = $2 AND kind = 'STATE'", f.org, inc.ID); n != 1 {
		t.Errorf("state events %d", n)
	}
}

// TestT042_AlertReadsFilterBeforeCounting: a caller with incident.read on
// one team's agents sees only alerts about those agents; hidden alerts are
// neither listed nor counted (D8).
func TestT042_AlertReadsFilterBeforeCounting(t *testing.T) {
	f := newFixture(t, billing.Community)
	f.raise(t, f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA))
	hidden := f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentB)
	hidden.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agentB.String()}}
	f.raise(t, hidden)
	all, err := f.svc.ListAlerts(f.as(td.RoleSecurityAdmin), reflexapp.AlertFilter{}, 50, "")
	if err != nil || len(all.Items) != 2 {
		t.Fatalf("org reader: %v %d", err, len(all.Items))
	}
	if _, err := f.svc.ListAlerts(f.as(td.RoleDeveloper), reflexapp.AlertFilter{}, 50, ""); err == nil {
		t.Error("a caller without incident.read listed alerts")
	}
}

const customRule = `id: org.kill_watch
version: "1"
title: Kill switch watch
description: Tells the team when the kill switch is engaged.
severity: HIGH
attention: INCIDENT
basis: OBSERVED
edition: business
on: [audit.security.kill_switch_engaged]
tests:
  - name: engaged
    fires: true
    events:
      - {kind: audit.security.kill_switch_engaged}
  - name: restored
    fires: false
    events:
      - {kind: audit.security.kill_switch_restored}
`

// TestHR241_CustomRulesPublishOnlyWithPassingTests: a custom rule is
// Business, alert-only (no PAGE), publishes only with a passing firing and
// non-firing test, and its publication records its content digest in the
// ledger.
func TestHR241_CustomRulesPublishOnlyWithPassingTests(t *testing.T) {
	f := newFixture(t, billing.Business)
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	det := &reflexapp.Detections{Pool: f.p, Env: env, Ents: ents{billing.Business}}
	ctx := f.as(td.RoleSecurityAdmin)
	if _, err := (&reflexapp.Detections{Pool: f.p, Env: env, Ents: ents{billing.Team}}).CreateCustomRule(ctx, customRule); !errors.Is(err, reflexapp.ErrEdition) {
		t.Errorf("Team: %v, want EDITION_REQUIRED", err)
	}
	if _, err := det.CreateCustomRule(ctx, strings.Replace(customRule, "attention: INCIDENT", "attention: PAGE", 1)); err == nil {
		t.Error("a PAGE custom rule was accepted")
	}
	quiet := strings.Replace(customRule, "    fires: true", "    fires: false", 1)
	r, err := det.CreateCustomRule(ctx, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := det.PublishCustomRule(ctx, r.Custom.ID); !errors.Is(err, reflexapp.ErrTestsFailed) {
		t.Errorf("publishing without a firing test: %v", err)
	}
	r, err = det.CreateCustomRule(ctx, customRule)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := det.PublishCustomRule(f.as(td.RoleViewer), r.Custom.ID); err == nil {
		t.Error("a viewer published")
	}
	pub, results, err := det.PublishCustomRule(ctx, r.Custom.ID)
	if err != nil || pub.Custom.State != "PUBLISHED" || len(results) != 2 || pub.Custom.LedgerEntryID == nil {
		t.Fatalf("publish: %v %+v", err, pub.Custom)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND id = $2 AND kind = 'audit.detection.rule_published'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'content_digest' = $3`, f.org, *pub.Custom.LedgerEntryID, pub.Digest); n != 1 {
		t.Error("the publication did not record the content digest")
	}
	if _, _, err := det.PublishCustomRule(ctx, r.Custom.ID); !errors.Is(err, reflexapp.ErrState) {
		t.Errorf("publishing twice: %v", err)
	}
	// The content is immutable.
	err = f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.custom_detection_rules SET content = 'x' WHERE org_id = $1", f.org)
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Errorf("content update: %v, want permission denied", err)
	}
}

// TestT106_EndingASuppressionReopensItsAlerts: ending a suppression opens
// its suppressed alerts again, and a responder can settle a suppressed
// alert directly (D59 M1).
func TestT106_EndingASuppressionReopensItsAlerts(t *testing.T) {
	f := newFixture(t, billing.Team)
	ctx := f.as(td.RoleSecurityAdmin)
	sup, err := f.svc.CreateSuppression(ctx, reflexapp.SuppressionRequest{
		Rule: rule, MaxSeverity: reflexdomain.SeverityHigh, Reason: "maintenance", ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := f.raise(t, f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentA))
	other := f.signal(rule, reflexdomain.SeverityMedium, reflexdomain.AttentionAlert, f.agentB)
	other.DedupeKey = "other"
	b := f.raise(t, other)
	if a.State != alerts.StateSuppressed || b.State != alerts.StateSuppressed {
		t.Fatalf("%+v %+v", a, b)
	}
	if got, err := f.svc.SetAlertState(ctx, b.Alert, alerts.StateResolved, "known"); err != nil || got.State != alerts.StateResolved ||
		got.SuppressionID != nil {
		t.Fatalf("settling a suppressed alert: %v %+v", err, got)
	}
	if _, err := f.svc.EndSuppression(ctx, sup.ID, "maintenance over"); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.alerts WHERE org_id = $1 AND id = $2 AND state = 'OPEN' AND suppression_id IS NULL",
		f.org, a.Alert); n != 1 {
		t.Error("ending the suppression left its alert suppressed")
	}
}
