// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package outcomes_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	cdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/outcomes"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Edition(e)
	return x, nil
}

// fx is a Business org with one agent and run. Its collection started 60
// days ago unless a test says otherwise, so the windows are collected.
type fx struct {
	t               *testing.T
	d               *dbtest.DB
	p               *db.Pool
	org             ids.OrgID
	team, env       ids.UUID
	agent, run      ids.UUID
	user            ids.UUID
	svc             *outcomes.Service
	roll            *outcomes.Rollup
	cases           *capp.Service
	sa, auto, ver   ids.UUID
	ceiling         ids.UUID
	automationReady bool
}

func newFx(t *testing.T) *fx {
	t.Helper()
	d := dbtest.New(t)
	return newFxOn(t, d)
}

func newFxOn(t *testing.T, d *dbtest.DB) *fx {
	t.Helper()
	f := &fx{
		t: t, d: d, p: d.AppPool(t), org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(),
		agent: ids.NewV7(), run: ids.NewV7(), user: ids.NewV7(),
	}
	f.svc = &outcomes.Service{Pool: f.p, Ents: edition(billing.Business)}
	f.roll = &outcomes.Rollup{Pool: f.p, Ents: edition(billing.Business), Failures: &failures.Sink{}}
	f.cases = &capp.Service{Pool: f.p, Editions: edition(billing.Business)}
	f.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", f.org)
	f.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.org, f.user)
	f.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'a', 'A')", f.org, f.team)
	f.exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'a', 'A', 'PRODUCTION')", f.org, f.env, f.team)
	f.exec(`INSERT INTO pc.agents (org_id, id, name, state, created_by, team_id, environment_id, owner_user_id, execution_context, claimed_at)
		VALUES ($1, $2, 'bot', 'VERIFIED', 'test', $3, $4, $5, 'service', now())`, f.org, f.agent, f.team, f.env, f.user)
	f.exec(`INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '1 hour')`, f.org, f.run, f.agent, f.env, f.user)
	return f
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

func (f *fx) collecting() {
	f.t.Helper()
	f.d.AdminExec(f.t, "INSERT INTO pc.outcome_collection (org_id, started_at) VALUES ($1, now() - interval '60 days')", f.org)
}

// rollup runs tonight's rollup afresh: it runs once per window end.
func (f *fx) rollup() int {
	f.t.Helper()
	f.d.AdminExec(f.t, "DELETE FROM pc.outcome_metric_samples WHERE org_id = $1", f.org)
	n, err := f.roll.Run(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) as(role td.RoleName, scope td.Scope) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}})
}

func (f *fx) auditor() context.Context {
	return f.as(td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
}

func (f *fx) responder() context.Context {
	return f.as(td.RoleResponder, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
}

// read returns tonight's 7-day point of a metric and dimension.
func (f *fx) read(ctx context.Context, metric, dim string) outcomes.Point {
	f.t.Helper()
	end := time.Now().UTC().Truncate(24 * time.Hour)
	r, err := f.svc.GetMetrics(ctx, []string{metric}, 7, end.AddDate(0, 0, -1), end)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, s := range r.Series {
		if s.Definition.Name == metric && s.Dimension == dim {
			if len(s.Points) != 1 {
				f.t.Fatalf("%s: %d points", metric, len(s.Points))
			}
			return s.Points[0]
		}
	}
	f.t.Fatalf("no series %s/%q in %+v", metric, dim, r.Series)
	return outcomes.Point{}
}

func reason(p outcomes.Point, code string) (outcomes.Reason, bool) {
	i := slices.IndexFunc(p.Reasons, func(r outcomes.Reason) bool { return r.Code == code })
	if i < 0 {
		return outcomes.Reason{}, false
	}
	return p.Reasons[i], true
}

// txn records a decision two days ago, inside tonight's 7-day window.
func (f *fx) txn(decision, mode string, simulated bool) ids.UUID {
	f.t.Helper()
	return f.txnAt(decision, mode, simulated, "2 days")
}

// txnAt records a decision that long ago.
func (f *fx) txnAt(decision, mode string, simulated bool, ago string) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, mode, simulated, created_at)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', $6, 'R', 'gw', $7, $8, now() - $9::interval)`,
		f.org, id, f.run, ids.NewV7(), make([]byte, 32), decision, mode, simulated, ago)
	return id
}

// incident opens an incident three days ago, with an alert a day earlier.
func (f *fx) incident(test bool) ids.UUID {
	f.t.Helper()
	inc := ids.NewV7()
	f.exec(`INSERT INTO pc.incidents (org_id, id, title, severity, opened_by, test) VALUES ($1, $2, 'stolen key', 'HIGH', 'alert:x', $3)`, f.org, inc, test)
	f.exec(`INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, dedupe_key, first_seen, last_seen, incident_id, test)
		VALUES ($1, $2, 'detection', 'stolen key', 'HIGH', 'ALERT', 'RULE_MATCH', $3, now(), now(), $4, $5)`,
		f.org, ids.NewV7(), ids.NewV7().String(), inc, test)
	f.d.AdminExec(f.t, "UPDATE pc.incidents SET created_at = now() - interval '3 days' WHERE org_id = $1 AND id = $2", f.org, inc)
	f.d.AdminExec(f.t, "UPDATE pc.alerts SET created_at = now() - interval '4 days' WHERE org_id = $1 AND incident_id = $2", f.org, inc)
	return inc
}

// action records a response action for an incident or case, requested
// three days ago.
func (f *fx) action(incident, kase *ids.UUID) ids.UUID {
	f.t.Helper()
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.response_actions (org_id, id, kind, scope_type, scope_id, reason, case_id, incident_id, actor, source, requested_at)
		VALUES ($1, $2, 'REVOKE', 'agent', $3, 'contain it', $4, $5, 'user:x', 'PERSON', now() - interval '3 days')`,
		f.org, id, f.agent.String(), kase, incident)
	return id
}

func (f *fx) settle(action ids.UUID, status string) {
	f.t.Helper()
	f.d.AdminExec(f.t, "UPDATE pc.response_actions SET status = $3, settled_at = now() - interval '2 days' WHERE org_id = $1 AND id = $2",
		f.org, action, status)
}

func (f *fx) setIncident(id ids.UUID, from, to string) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).SetIncidentState(ctx, dbq.SetIncidentStateParams{OrgID: f.org, ID: id, FromState: from, ToState: to})
		if err == nil && n != 1 {
			return errors.New("no incident moved")
		}
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) openCase() cdomain.Case {
	f.t.Helper()
	c, err := f.cases.Open(f.responder(), capp.OpenRequest{
		Title: "stolen key", Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agent.String()}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fx) caseContainedAt(id ids.UUID) *time.Time {
	f.t.Helper()
	var at *time.Time
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT contained_at FROM pc.cases WHERE org_id = $1 AND id = $2", f.org, id).Scan(&at)
	}); err != nil {
		f.t.Fatal(err)
	}
	return at
}

// TestHR537_AnEmptyWindowIsNotCollected: an org with nothing to measure
// reads NOT_COLLECTED for every metric, with no value and a stated reason,
// and the database refuses a 0 without a measured case.
// Covers: F774
func TestHR537_AnEmptyWindowIsNotCollected(t *testing.T) {
	f := newFx(t)
	f.collecting()
	if n := f.rollup(); n == 0 {
		t.Fatal("nothing written")
	}
	if n, err := f.roll.Run(context.Background(), f.org); err != nil || n != 0 {
		t.Fatalf("a second run wrote %d: %v", n, err)
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	for _, days := range outcomes.Windows {
		r, err := f.svc.GetMetrics(f.auditor(), nil, days, end.AddDate(0, 0, -1), end)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Series) < len(outcomes.Definitions) {
			t.Fatalf("%d series", len(r.Series))
		}
		for _, s := range r.Series {
			p := s.Points[0]
			if p.State != outcomes.NotCollected || p.P50 != nil || p.P90 != nil || p.Share != nil || p.Measured != 0 || len(p.Reasons) == 0 {
				t.Fatalf("%s/%s: %+v", s.Definition.Name, s.Dimension, p)
			}
		}
	}

	for _, ins := range []string{
		`INSERT INTO pc.outcome_metric_samples (org_id, id, metric, window_start, window_end, share, measured, unmeasured, reasons, collected)
			VALUES ($1, $2, 'friction.hold_share', '2026-01-01Z', '2026-01-08Z', 0, 0, 0, '[]', true)`,
		`INSERT INTO pc.outcome_metric_samples (org_id, id, metric, window_start, window_end, share, measured, unmeasured, reasons, collected)
			VALUES ($1, $2, 'friction.hold_share', '2026-01-01Z', '2026-01-08Z', 0, 0, 0, '[{"code":"X","count":0}]', false)`,
		`INSERT INTO pc.outcome_metric_samples (org_id, id, metric, window_start, window_end, measured, unmeasured, reasons, collected)
			VALUES ($1, $2, 'friction.hold_share', '2026-01-01Z', '2026-01-08Z', 0, 0, '[]', false)`,
	} {
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, ins, f.org, ids.NewV7())
			return err
		}); err == nil {
			t.Fatalf("the database took: %s", ins)
		}
	}
}

// TestHR537_WindowsBeforeCollectionAreNotCollected: an org's first rollup
// starts its collection. Older records are not backfilled, however many.
// Covers: F774
func TestHR537_WindowsBeforeCollectionAreNotCollected(t *testing.T) {
	f := newFx(t)
	f.txn("REQUIRE_APPROVAL", "enforce", false)
	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricHoldShare, "")
	if p.State != outcomes.NotCollected || p.Share != nil || p.Measured != 0 {
		t.Fatalf("%+v", p)
	}
	if _, ok := reason(p, outcomes.ReasonCollectionNotStarted); !ok {
		t.Fatalf("%+v", p.Reasons)
	}
}

// TestHR538_RequestedContainmentIsNeverConfirmed: an action only requested
// and an incident only declared contained are unmeasured, whatever the
// clock says. Confirming the action makes the same incident measured, with
// requested-to-confirmed reported apart. A test incident is never counted.
// Covers: F774
func TestHR538_RequestedContainmentIsNeverConfirmed(t *testing.T) {
	f := newFx(t)
	f.collecting()
	inc := f.incident(false)
	act := f.action(&inc, nil)
	f.setIncident(inc, "OPEN", "CONTAINED")
	test := f.incident(true)
	testAct := f.action(&test, nil)

	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricContainmentTime, "")
	if p.State != outcomes.NotCollected || p.P50 != nil || p.Measured != 0 {
		t.Fatalf("requested and declared: %+v", p)
	}
	if r, ok := reason(p, outcomes.ReasonRequestedNotConfirmed); !ok || r.Count != 1 || r.OldestAgeSeconds == nil {
		t.Fatalf("reasons: %+v", p.Reasons)
	}
	q := f.read(f.auditor(), outcomes.MetricRequestedToConfirm, "")
	if q.State != outcomes.NotCollected || q.Measured != 0 {
		t.Fatalf("requested to confirmed: %+v", q)
	}
	if r, ok := reason(q, outcomes.ReasonRequestedNotConfirmed); !ok || r.Count != 1 {
		t.Fatalf("only the real request stands unconfirmed: %+v", q.Reasons)
	}

	f.settle(act, "FAILED")
	f.rollup()
	p = f.read(f.auditor(), outcomes.MetricContainmentTime, "")
	if _, ok := reason(p, outcomes.ReasonFailedOrUnsupported); p.State != outcomes.NotCollected || !ok {
		t.Fatalf("a failed action counted as contained: %+v", p)
	}

	f.d.AdminExec(t, "UPDATE pc.response_actions SET status = 'REQUESTED', settled_at = NULL WHERE org_id = $1 AND id = $2", f.org, act)
	f.settle(act, "CONFIRMED")
	f.settle(testAct, "CONFIRMED")
	f.rollup()
	p = f.read(f.auditor(), outcomes.MetricContainmentTime, "")
	// From the alert, four days ago, to the action, two days ago.
	if p.State != outcomes.Collected || p.Measured != 1 || p.P50 == nil || *p.P50 < 47*3600 || *p.P50 > 49*3600 {
		t.Fatalf("confirmed: %+v", p)
	}
	q = f.read(f.auditor(), outcomes.MetricRequestedToConfirm, "")
	if q.State != outcomes.Collected || q.Measured != 1 || *q.P50 < 23*3600 || *q.P50 > 25*3600 {
		t.Fatalf("requested to confirmed: %+v", q)
	}
}

// TestHR538_ACaseIsContainedOnlyThroughConfirmedContainment: a reason that
// no containment is needed never sets contained_at; a close over a confirmed
// action does, once, and a reopened case keeps the first time.
// Covers: F774
func TestHR538_ACaseIsContainedOnlyThroughConfirmedContainment(t *testing.T) {
	f := newFx(t)
	f.collecting()
	ctx := f.responder()

	none := f.openCase()
	if _, err := f.cases.Append(ctx, none.ID, cdomain.Draft{
		Kind: cdomain.KindState, State: cdomain.StateContained, NoContainmentNeeded: true, Reason: "a false alarm",
	}); err != nil {
		t.Fatal(err)
	}
	if at := f.caseContainedAt(none.ID); at != nil {
		t.Fatalf("no containment needed set contained_at: %v", at)
	}
	// The window ends at the last midnight; a case's time is otherwise fixed.
	f.d.AdminExec(t, "ALTER TABLE pc.cases DISABLE TRIGGER USER")
	f.d.AdminExec(t, "UPDATE pc.cases SET created_at = now() - interval '3 days' WHERE org_id = $1 AND id = $2", f.org, none.ID)
	f.d.AdminExec(t, "ALTER TABLE pc.cases ENABLE TRIGGER USER")
	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricContainmentTime, "")
	if _, ok := reason(p, outcomes.ReasonNoContainmentNeeded); p.State != outcomes.NotCollected || !ok {
		t.Fatalf("no containment needed: %+v", p)
	}

	real := f.openCase()
	act := f.action(nil, &real.ID)
	if _, err := f.cases.Append(ctx, real.ID, cdomain.Draft{Kind: cdomain.KindState, State: cdomain.StateContained}); err == nil {
		t.Fatal("a case closed over a requested action")
	}
	f.d.AdminExec(t, "UPDATE pc.response_actions SET status = 'CONFIRMED', settled_at = now() WHERE org_id = $1 AND id = $2", f.org, act)
	if _, err := f.cases.Append(ctx, real.ID, cdomain.Draft{Kind: cdomain.KindState, State: cdomain.StateContained}); err != nil {
		t.Fatal(err)
	}
	first := f.caseContainedAt(real.ID)
	if first == nil {
		t.Fatal("a confirmed close set no contained_at")
	}
	if _, err := f.cases.Append(ctx, real.ID, cdomain.Draft{Kind: cdomain.KindState, State: cdomain.StateOpen}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.cases.Append(ctx, real.ID, cdomain.Draft{Kind: cdomain.KindState, State: cdomain.StateContained}); err != nil {
		t.Fatal(err)
	}
	if again := f.caseContainedAt(real.ID); again == nil || !again.Equal(*first) {
		t.Fatalf("the first time moved: %v then %v", first, again)
	}
	// pc_app may not write the column.
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.cases SET contained_at = now() WHERE org_id = $1", f.org)
		return err
	}); err == nil {
		t.Fatal("pc_app wrote contained_at")
	}
}

// alertCase opens a case on an alert of its own, and requests an action on it.
func (f *fx) alertCase(test bool) ids.UUID {
	f.t.Helper()
	alert := ids.NewV7()
	f.exec(`INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, dedupe_key, first_seen, last_seen, test)
		VALUES ($1, $2, 'detection', 'stolen key', 'HIGH', 'ALERT', 'RULE_MATCH', $3, now(), now(), $4)`,
		f.org, alert, alert.String(), test)
	c, err := f.cases.Open(f.responder(), capp.OpenRequest{
		Title: "stolen key", Alert: &alert, Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: f.agent.String()}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.action(nil, &c.ID)
}

// TestHR538_AnActionOnATestAlertNeverCounts: an action on a case opened from
// a test alert is neither listed as unconfirmed nor measured once confirmed.
// The same action on a real alert's case is both.
// Covers: F774
func TestHR538_AnActionOnATestAlertNeverCounts(t *testing.T) {
	f := newFx(t)
	f.collecting()
	real, test := f.alertCase(false), f.alertCase(true)

	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricRequestedToConfirm, "")
	if r, ok := reason(p, outcomes.ReasonRequestedNotConfirmed); p.State != outcomes.NotCollected || !ok || r.Count != 1 {
		t.Fatalf("only the real alert's request stands unconfirmed: %+v", p)
	}

	f.settle(real, "CONFIRMED")
	f.settle(test, "CONFIRMED")
	f.rollup()
	p = f.read(f.auditor(), outcomes.MetricRequestedToConfirm, "")
	if p.State != outcomes.Collected || p.Measured != 1 {
		t.Fatalf("only the real alert's action is measured: %+v", p)
	}
}

// TestHR539_AVolumeIsOnlyADenominator: more records change a share or a
// duration and the count of measured cases, and nothing else; the samples
// have no column for a total.
// Covers: F774
func TestHR539_AVolumeIsOnlyADenominator(t *testing.T) {
	f := newFx(t)
	f.collecting()
	for range 3 {
		f.txn("ALLOW", "enforce", false)
	}
	f.txn("REQUIRE_APPROVAL", "enforce", false)
	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricHoldShare, "")
	if p.State != outcomes.Collected || p.Share == nil || *p.Share != 0.25 || p.Measured != 4 || p.P50 != nil {
		t.Fatalf("%+v", p)
	}
	var columns []string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'pc' AND table_name = 'outcome_metric_samples'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				return err
			}
			columns = append(columns, c)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"value", "total", "count", "time_saved"} {
		if slices.Contains(columns, banned) {
			t.Fatalf("a %q column stores a volume: %v", banned, columns)
		}
	}
}

// TestHR540_EveryMetricStatesItsScopeAndAsOf: every series names its scope,
// what it cannot see and that it is a draft; every sampled point its as-of.
// Covers: F774
func TestHR540_EveryMetricStatesItsScopeAndAsOf(t *testing.T) {
	f := newFx(t)
	f.collecting()
	f.txn("DENY", "enforce", false)
	f.rollup()
	end := time.Now().UTC().Truncate(24 * time.Hour)
	r, err := f.svc.GetMetrics(f.auditor(), nil, 7, end.AddDate(0, 0, -2), end)
	if err != nil {
		t.Fatal(err)
	}
	if r.AsOf.IsZero() {
		t.Fatal("no as-of")
	}
	for _, s := range r.Series {
		if s.Scope != outcomes.ScopeOrganization || len(s.Definition.NotSeen) == 0 || s.Definition.Status != outcomes.DefinitionSignedOff {
			t.Fatalf("%+v", s)
		}
		if len(s.Points) != 2 || s.Points[0].State != outcomes.NoSample {
			t.Fatalf("%s: a day without a rollup: %+v", s.Definition.Name, s.Points)
		}
		if p := s.Points[1]; p.AsOf.IsZero() || p.Window.Start.IsZero() || !p.Window.End.Equal(end) {
			t.Fatalf("%s: %+v", s.Definition.Name, p)
		}
	}
}

// TestT233_MisleadingOutcomeMetrics: simulated and monitor decisions never
// count, a viewer who may not read a metric's sources gets RESTRICTED with
// nothing of it, a narrower viewer and a lower edition are refused, another
// org's records are not this org's, and a lapsed edition stops the rollup.
// Covers: F774
func TestT233_MisleadingOutcomeMetrics(t *testing.T) {
	f := newFx(t)
	f.collecting()
	f.txn("REQUIRE_APPROVAL", "enforce", true)
	f.txn("REQUIRE_APPROVAL", "monitor", false)
	f.txn("ALLOW", "enforce", false)
	other := newFxOn(t, f.d)
	other.collecting()
	other.txn("REQUIRE_APPROVAL", "enforce", false)

	f.rollup()
	other.rollup()
	if p := f.read(f.auditor(), outcomes.MetricHoldShare, ""); p.State != outcomes.Collected || *p.Share != 0 || p.Measured != 1 {
		t.Fatalf("simulated or monitor decisions counted: %+v", p)
	}
	if p := other.read(other.auditor(), outcomes.MetricHoldShare, ""); *p.Share != 1 || p.Measured != 1 {
		t.Fatalf("the other org: %+v", p)
	}

	viewer := f.as(td.RoleViewer, td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()})
	if p := f.read(viewer, outcomes.MetricHoldShare, ""); p.State != outcomes.Restricted || p.Share != nil || p.Measured != 0 || p.AsOf != (time.Time{}) {
		t.Fatalf("restricted: %+v", p)
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	team := f.as(td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: f.team})
	if _, err := f.svc.GetMetrics(team, nil, 7, end.AddDate(0, 0, -1), end); !errors.Is(err, outcomes.ErrScope) {
		t.Fatalf("team viewer: %v", err)
	}
	for _, bad := range []struct {
		days       int
		start, end time.Time
		metrics    []string
	}{
		{3, end.AddDate(0, 0, -1), end, nil},
		{7, end.AddDate(0, 0, -31), end, nil},
		{7, end, end, nil},
		{7, end.AddDate(0, 0, -1), end, []string{"decisions.total"}},
	} {
		if _, err := f.svc.GetMetrics(f.auditor(), bad.metrics, bad.days, bad.start, bad.end); err == nil {
			t.Fatalf("read: %+v", bad)
		}
	}
	f.svc.Ents = edition(billing.Team)
	var pe *pcerr.Error
	if _, err := f.svc.GetMetrics(f.auditor(), nil, 7, end.AddDate(0, 0, -1), end); !errors.As(err, &pe) || pe.Reason() != "EDITION_REQUIRED" {
		t.Fatalf("team edition: %v", err)
	}

	// A lapsed edition stops quietly, keeps its samples and owns one failure.
	f.d.AdminExec(t, "DELETE FROM pc.outcome_metric_samples WHERE org_id = $1", f.org)
	f.roll.Ents = edition(billing.Team)
	for range 2 {
		if n, err := f.roll.Run(context.Background(), f.org); err != nil || n != 0 {
			t.Fatalf("lapsed: %d %v", n, err)
		}
	}
	var failed int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = 'outcomes.edition_lapsed'", f.org).Scan(&failed)
	}); err != nil || failed != 1 {
		t.Fatalf("failures: %d %v", failed, err)
	}
}

// TestF774_AgentMilestonesAreWrittenOnce: M1 counts an agent from its first
// enrolment to its first enforced decision and writes each time once. A later
// enforced decision moves neither, and an agent enrolled before collection
// is never measured or backfilled.
// Covers: F774
func TestF774_AgentMilestonesAreWrittenOnce(t *testing.T) {
	f := newFx(t)
	f.collecting()
	change := func(agent ids.UUID, at string) {
		f.exec(`INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, created_at)
			VALUES ($1, $2, $3, 'instance.admitted', 'test', now() - $4::interval)`, f.org, ids.NewV7(), agent, at)
	}
	change(f.agent, "5 days")
	old := ids.NewV7()
	f.exec(`INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'older', 'DISCOVERED', 'test')`, f.org, old)
	change(old, "90 days")

	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricProtectedWorkTime, "")
	if p.State != outcomes.NotCollected {
		t.Fatalf("no enforced decision yet: %+v", p)
	}
	if r, ok := reason(p, outcomes.ReasonOpenNoEnforcedDecision); !ok || r.Count != 1 || r.OldestAgeSeconds == nil {
		t.Fatalf("open: %+v", p.Reasons)
	}
	if r, ok := reason(p, outcomes.ReasonEnrolledBeforeTracking); !ok || r.Count != 1 {
		t.Fatalf("before tracking: %+v", p.Reasons)
	}

	f.txn("ALLOW", "enforce", true)
	f.txn("DENY", "enforce", false)
	f.rollup()
	p = f.read(f.auditor(), outcomes.MetricProtectedWorkTime, "")
	if p.State != outcomes.Collected || p.Measured != 1 || *p.P50 < 71*3600 || *p.P50 > 73*3600 {
		t.Fatalf("enforced: %+v", p)
	}

	f.d.AdminExec(t, "UPDATE pc.transactions SET created_at = created_at - interval '1 day' WHERE org_id = $1", f.org)
	f.rollup()
	if q := f.read(f.auditor(), outcomes.MetricProtectedWorkTime, ""); *q.P50 != *p.P50 {
		t.Fatalf("a milestone moved: %v then %v", *p.P50, *q.P50)
	}
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.agent_milestones SET at = now() WHERE org_id = $1", f.org)
		return err
	}); err == nil {
		t.Fatal("pc_app moved a milestone")
	}
}

// TestF774_ExplanationFirstViews: M2 records a person's first read of a
// non-ALLOW decision once; a service account's read and an ALLOW are not
// views; unread decisions are shown with their age, never as 0 seconds.
// Covers: F774
func TestF774_ExplanationFirstViews(t *testing.T) {
	f := newFx(t)
	f.collecting()
	read, unread, allow := f.txn("DENY", "enforce", false), f.txn("DENY", "enforce", false), f.txn("ALLOW", "enforce", false)
	e := &tapp.Explorer{Pool: f.p}
	bot := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
	}})
	if err := e.NoteExplanationView(bot, read); err != nil {
		t.Fatal(err)
	}
	f.rollup()
	if p := f.read(f.auditor(), outcomes.MetricExplanationTime, ""); p.State != outcomes.NotCollected || p.P50 != nil {
		t.Fatalf("a service account's read counted: %+v", p)
	}

	person := f.auditor()
	for _, id := range []ids.UUID{read, read, allow} {
		if err := e.NoteExplanationView(person, id); err != nil {
			t.Fatal(err)
		}
	}
	var first, views int
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE transaction_id = $2) FROM pc.explanation_views WHERE org_id = $1`,
			f.org, read).Scan(&views, &first)
	}); err != nil || views != 1 || first != 1 {
		t.Fatalf("views: %d %d %v", views, first, err)
	}
	f.d.AdminExec(t, "UPDATE pc.explanation_views SET first_viewed_at = now() - interval '1 day' WHERE org_id = $1", f.org)
	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricExplanationTime, "")
	if p.State != outcomes.Collected || p.Measured != 1 || *p.P50 < 23*3600 || *p.P50 > 25*3600 {
		t.Fatalf("read: %+v", p)
	}
	if r, ok := reason(p, outcomes.ReasonUnread); !ok || r.Count != 1 || r.OldestAgeSeconds == nil || *r.OldestAgeSeconds <= 0 {
		t.Fatalf("unread %s: %+v", unread, p.Reasons)
	}
	if d := f.read(f.auditor(), outcomes.MetricExplanationShare, ""); d.State != outcomes.Collected || d.Measured != 2 || *d.Share != 0 {
		t.Fatalf("no decision here has a receipt: %+v", d)
	}
}

// approval records a waiting restoration approval, on an agent of its own:
// an agent has one live restoration.
func (f *fx) approval() ids.UUID {
	f.t.Helper()
	id, agent := ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'test')`, f.org, agent, "bot-"+agent.String())
	f.exec(`INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, requested_by, operation, binding, binding_input,
		requirements, display, display_hash, deadline_at)
		VALUES ($1, $2, 'RESTORATION', $3, $4, 'agent.restore', $5, '\x7b7d', '[{"kind":"approval","role":"approver","count":1,"sources":[]}]',
		        '{}', $5, date_trunc('second', now()) + interval '1 day')`,
		f.org, id, agent, f.user, append(append([]byte{}, id[:]...), id[:]...))
	return id
}

func (f *fx) inTx(fn func(q *dbq.Queries) error) {
	f.t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(dbq.New(tx))
	}); err != nil {
		f.t.Fatal(err)
	}
}

// TestF774_FirstDecisionSurvivesARequeue: M4 keeps the first decision when
// a void re-queues an approval, which loses approved_at. An approval never
// decided is listed, not measured.
// Covers: F774
func TestF774_FirstDecisionSurvivesARequeue(t *testing.T) {
	f := newFx(t)
	f.collecting()
	ctx := context.Background()
	id := f.approval()
	waiting := f.approval()
	declined := f.approval()
	f.d.AdminExec(t, "UPDATE pc.approval_requests SET created_at = created_at - interval '3 days', deadline_at = date_trunc('second', now()) + interval '1 day' WHERE org_id = $1", f.org)

	first := func(id ids.UUID) *time.Time {
		var at *time.Time
		if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT first_decided_at FROM pc.approval_requests WHERE org_id = $1 AND id = $2", f.org, id).Scan(&at)
		}); err != nil {
			t.Fatal(err)
		}
		return at
	}
	later := time.Now().Add(time.Hour)
	f.inTx(func(q *dbq.Queries) error {
		_, err := q.MarkApproved(ctx, &later, f.org, id)
		return err
	})
	at := first(id)
	if at == nil {
		t.Fatal("approving set no first decision")
	}
	f.inTx(func(q *dbq.Queries) error {
		n, err := q.ReopenApprovalRequest(ctx, f.org, id)
		if err == nil && n != 1 {
			return errors.New("not re-queued")
		}
		return err
	})
	f.inTx(func(q *dbq.Queries) error {
		_, err := q.MarkApproved(ctx, &later, f.org, id)
		return err
	})
	if again := first(id); again == nil || !again.Equal(*at) {
		t.Fatalf("the first decision moved: %v then %v", at, again)
	}
	f.inTx(func(q *dbq.Queries) error {
		reason := "NO"
		_, err := q.DeclineApprovalRequest(ctx, &reason, f.org, declined)
		return err
	})
	if first(declined) == nil {
		t.Fatal("declining set no first decision")
	}
	f.d.AdminExec(t, "UPDATE pc.approval_requests SET first_decided_at = first_decided_at - interval '2 days' WHERE org_id = $1 AND id <> $2", f.org, waiting)
	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricApprovalWait, "")
	if p.State != outcomes.Collected || p.Measured != 2 || *p.P50 < 23*3600 || *p.P50 > 25*3600 {
		t.Fatalf("waits: %+v", p)
	}
	if r, ok := reason(p, outcomes.ReasonOpenWaiting); !ok || r.Count != 1 {
		t.Fatalf("waiting: %+v", p.Reasons)
	}
}

// exception records an activated exception for the fixture's agent and the
// operation of txn, created that long ago. Its time is the database's.
func (f *fx) exception(ago string) {
	f.t.Helper()
	f.d.AdminExec(f.t, "ALTER TABLE pc.policy_exceptions DISABLE TRIGGER USER")
	defer f.d.AdminExec(f.t, "ALTER TABLE pc.policy_exceptions ENABLE TRIGGER USER")
	f.d.AdminExec(f.t, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason,
		owner_id, requested_by, requested_expiry, state, activated_at, expires_at, created_at)
		VALUES ($1, $2, 'refunds', 'r1', $3, $4, ARRAY['payments.refund.create'], 'a known refund', $5, $5,
		        now() - $6::interval + interval '2 days', 'ACTIVE', now() - $6::interval + interval '1 hour',
		        now() - $6::interval + interval '2 days', now() - $6::interval)`,
		f.org, ids.NewV7(), make([]byte, 32), f.agent, f.user, ago)
}

// TestF774_TheOverrideRateIsMeasuredOnSevenDays: the 7-day window measures
// the DENYs whose 7 days after ended inside it, so a DENY older than the
// window counts, and one younger than 7 days is listed as still running.
// Covers: F774
func TestF774_TheOverrideRateIsMeasuredOnSevenDays(t *testing.T) {
	f := newFx(t)
	f.collecting()
	f.txnAt("DENY", "enforce", false, "9 days")
	f.txnAt("DENY", "enforce", false, "10 days")
	f.txnAt("DENY", "enforce", false, "20 days") // Its 7 days ended before the window.
	f.txn("DENY", "enforce", false)
	f.exception("8 days")
	f.rollup()
	p := f.read(f.auditor(), outcomes.MetricOverrideShare, "")
	// Both settled DENYs came before the exception, and within 7 days of it.
	if p.State != outcomes.Collected || p.Measured != 2 || p.Share == nil || *p.Share != 1 {
		t.Fatalf("overrides: %+v", p)
	}
	if r, ok := reason(p, outcomes.ReasonFollowUpRunning); !ok || r.Count != 1 {
		t.Fatalf("running: %+v", p.Reasons)
	}
}

// TestF774_RolloutStagesAreKept: every stage a rollout reaches is recorded,
// which stage_changed_at overwrites. M5 shows each check of a published
// version apart.
// Covers: F774
func TestF774_RolloutStagesAreKept(t *testing.T) {
	f := newFx(t)
	f.collecting()
	policy, version, rollout := ids.NewV7(), ids.NewV7(), ids.NewV7()
	f.exec("INSERT INTO pc.policies (org_id, id, bundle_id) VALUES ($1, $2, 'refunds')", f.org, policy)
	f.exec(`INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, content_digest, created_by)
		VALUES ($1, $2, $3, 1, '{}', $4, 'test')`, f.org, version, policy, make([]byte, 32))
	f.exec(`INSERT INTO pc.policy_rollouts (org_id, id, version_id, stage, created_by) VALUES ($1, $2, $3, 'SHADOW', 'test')`, f.org, rollout, version)
	// Before it ends: a finished rollout takes no write.
	f.d.AdminExec(t, "UPDATE pc.policy_rollouts SET created_at = now() - interval '2 days' WHERE org_id = $1", f.org)
	// PILOT twice: a write that keeps the stage records nothing.
	for _, s := range []string{"PILOT", "PILOT", "COMPLETE"} {
		f.exec("UPDATE pc.policy_rollouts SET stage = $3 WHERE org_id = $1 AND id = $2", f.org, rollout, s)
	}
	var got []string
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT coalesce(from_stage, '') || '>' || to_stage FROM pc.policy_rollout_stage_events WHERE org_id = $1 ORDER BY at, to_stage DESC", f.org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return err
			}
			got = append(got, s)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{">SHADOW", "SHADOW>PILOT", "PILOT>COMPLETE"}
	if len(got) != len(want) {
		t.Fatalf("stages: %v", got)
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Fatalf("stages: %v", got)
		}
	}

	f.exec(`UPDATE pc.policy_versions SET state = 'PUBLISHED', published_by = 'test', published_at = now() WHERE org_id = $1 AND id = $2`, f.org, version)
	f.d.AdminExec(t, "UPDATE pc.policy_versions SET published_at = now() - interval '1 day' WHERE org_id = $1", f.org)
	f.rollup()
	if p := f.read(f.auditor(), outcomes.MetricStagedShare, outcomes.DimensionPolicy); p.State != outcomes.Collected || *p.Share != 1 {
		t.Fatalf("staged: %+v", p)
	}
	if p := f.read(f.auditor(), outcomes.MetricValidatedShare, outcomes.DimensionPolicy); p.State != outcomes.Collected || *p.Share != 0 {
		t.Fatalf("validated: %+v", p)
	}
	p := f.read(f.auditor(), outcomes.MetricStagedShare, outcomes.DimensionAutomation)
	if _, ok := reason(p, outcomes.ReasonRolloutHistoryUnknown); p.State != outcomes.NotCollected || !ok {
		t.Fatalf("automation rollouts have no history: %+v", p)
	}
}

// automationExec records a LIVE execution that ended in state two days ago.
func (f *fx) automationExec(state string) ids.UUID {
	f.t.Helper()
	if !f.automationReady {
		f.sa, f.auto, f.ver, f.ceiling = ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
		// The account and the automation reference each other: one statement.
		f.exec(`WITH sa AS (
				INSERT INTO pc.service_accounts (org_id, id, name, created_by, automation_id)
				VALUES ($1, $2, 'triage-sa', 'test', $3) RETURNING id)
			INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
			SELECT $1, $3, 'triage', 'Triage alerts', 'SECURITY_WORK', $4, sa.id, $4 FROM sa`, f.org, f.sa, f.auto, f.user)
		f.exec(`INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
			VALUES ($1, $2, $3, 1, '{}', $5, $4)`, f.org, f.ver, f.auto, f.user, make([]byte, 32))
		request := ids.NewV7()
		f.exec(`INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
			requested_by, expires_at) VALUES ($1, $2, 'automation', 'ENABLE', $3, $4, $4, '{}', 1, 'user:test', now() + interval '1 hour')`,
			f.org, request, f.auto, make([]byte, 32))
		f.exec(`INSERT INTO pc.automation_ceilings (org_id, id, automation_id, version_id, digest, approved_by, change_request_id,
			review_by) VALUES ($1, $2, $3, $4, $5, ARRAY[$6::uuid], $7, now() + interval '30 days')`,
			f.org, f.ceiling, f.auto, f.ver, make([]byte, 32), f.user, request)
		f.automationReady = true
	}
	trigger, id := ids.NewV7(), ids.NewV7()
	f.exec(`INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref, authenticity,
		root_trigger_id, state, occurred_at) VALUES ($1, $4, $3, $2, 'MANUAL', 'LIVE', 'test', 'USER_SESSION', $4, 'ACCEPTED', now())`,
		f.org, f.ver, f.auto, trigger)
	f.exec(`INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode, ceiling_id,
		service_account_id, principal_sa_id, trigger_kind, occurred_at, root_trigger_id, deadline_at)
		VALUES ($1, $2, $3, $4, $5, 'LIVE', $6, $7, $7, 'MANUAL', now(), $5, now() + interval '1 hour')`,
		f.org, id, f.auto, f.ver, trigger, f.ceiling, f.sa)
	f.d.AdminExec(f.t, "ALTER TABLE pc.automation_executions DISABLE TRIGGER USER")
	defer f.d.AdminExec(f.t, "ALTER TABLE pc.automation_executions ENABLE TRIGGER USER")
	f.d.AdminExec(f.t, "UPDATE pc.automation_executions SET state = $3, ended_at = now() - interval '2 days', result = '{}', reason = 'TEST_END' WHERE org_id = $1 AND id = $2", f.org, id, state)
	return id
}

// TestF774_CancelledKeepsItsOwnBucket: M6 and the hourly metric each report
// cancelled executions as cancelled, in no other bucket. Per automation,
// every state has its own share, SHADOW and TEST runs excluded, and a person
// reverting an automation's action counts only through its execution link.
// Covers: F774
func TestF774_CancelledKeepsItsOwnBucket(t *testing.T) {
	f := newFx(t)
	f.collecting()
	f.automationExec("CANCELLED")
	failed := f.automationExec("FAILED")

	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.MetricAutomationOutcomes(ctx, f.org, time.Now().Add(-72*time.Hour), time.Now())
		if err != nil {
			return err
		}
		got := map[string]int64{}
		for _, r := range rows {
			got[r.Outcome] = r.N
		}
		if got[operations.OutcomeCancelled] != 1 || got[operations.OutcomeFailed] != 1 || len(got) != 2 {
			t.Fatalf("outcomes: %v", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	act := f.action(nil, nil)
	f.d.AdminExec(t, "UPDATE pc.response_actions SET execution_id = $3 WHERE org_id = $1 AND id = $2", f.org, act, failed)
	f.rollup()
	dim := f.auto.String()
	for metric, want := range map[string]float64{
		outcomes.MetricCancelledShare: 0.5, outcomes.MetricFailedShare: 0.5, outcomes.MetricEvidenceShare: 0,
		outcomes.MetricPartialShare: 0, outcomes.MetricReconciliationShare: 0, outcomes.MetricRevertedShare: 0,
	} {
		if p := f.read(f.auditor(), metric, dim); p.State != outcomes.Collected || p.Measured != 2 || *p.Share != want {
			t.Fatalf("%s: %+v", metric, p)
		}
	}
}
