// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgranges_test

import (
	"context"
	"errors"
	"testing"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition, x.Limits.MaxAgents = billing.Edition(e), billing.Unlimited
	return x, nil
}

type world struct {
	pool, admin  *db.Pool
	svc          *app.Service
	org          ids.OrgID
	team, env    ids.UUID
	owner        ids.UUID
	rangeAgent   ids.UUID
	realAgent    ids.UUID
	run, realRun ids.UUID
}

func newWorld(t *testing.T, d *dbtest.DB) *world {
	t.Helper()
	p := d.AppPool(t)
	w := &world{
		pool: p, admin: d.Pool(t, d.Migrator), org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7(),
		run: ids.NewV7(), realRun: ids.NewV7(),
	}
	w.svc = &app.Service{Store: pgranges.Store{Pool: p}, Editions: edition(billing.Team)}
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", w.org, w.team)
	w.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", w.org, w.env, w.team)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.owner)
	inv := aapp.NewInventory(p, edition(billing.Business))
	for i, rng := range []bool{true, false} {
		a, err := inv.Create(w.as(td.RoleAgentOwner), adomain.Details{
			Name: []string{"range-coder", "real-coder"}[i], TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner,
			Context: adomain.ContextCI, RangeAgent: rng,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rng {
			w.rangeAgent = a.ID
		} else {
			w.realAgent = a.ID
		}
	}
	w.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at, simulated)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours', true)`, w.org, w.run, w.rangeAgent, w.env, w.owner)
	w.exec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_user_id, principal_user_id, principal_source, expires_at)
		VALUES ($1, $2, $3, $4, $5, $5, 'launcher', now() + interval '8 hours')`, w.org, w.realRun, w.realAgent, w.env, w.owner)
	return w
}

func (w *world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) count(t *testing.T, org ids.OrgID, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (w *world) as(roles ...td.RoleName) context.Context { return w.asIn(w.org, roles...) }

func (w *world) asIn(org ids.OrgID, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.owner}, Bindings: bs}, Credential: tenancy.CredAccessToken,
	})
}

// txn inserts a transaction of a run with decision and reason.
func (w *world) txn(t *testing.T, run ids.UUID, simulated bool, decision, reason string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	w.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state, simulated)
		VALUES ($1, $2, $3, $4, $5, 'github.pull_request.merge', $6, $7, 'gw', 'OPEN', $8)`,
		w.org, id, run, ids.NewV7(), make([]byte, 32), decision, reason, simulated)
	return id
}

func decl(id string) domain.Scenario {
	return domain.Scenario{ID: id, Digest: hexA, Tier: domain.TierCommunity, Category: "boundary", Suite: "coding-agent", Title: id, StepCount: 1}
}

func (w *world) start(t *testing.T, ids ...string) domain.Range {
	t.Helper()
	var set []domain.Scenario
	for _, id := range ids {
		set = append(set, decl(id))
	}
	r, err := w.svc.StartRange(w.as(td.RoleAgentOwner), app.StartInput{Agent: w.rangeAgent, Scenarios: set, RunnerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var deny = domain.Expect{Outcome: domain.OutcomeDeny, Reason: "DESTINATION_NOT_GRANTED"}

func uid(id ids.UUID) *ids.UUID { return &id }

// TestHR224_ServerRecordsWinOverClientClaims (integration): the range runs
// on the real tables. A simulated transaction the server decided ALLOW
// beats the runner's claim of DENY; a real run's transaction cannot back a
// step; the result is stored with the server's value and MISMATCH.
func TestHR224_ServerRecordsWinOverClientClaims(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	ctx := w.as(td.RoleAgentOwner)
	before := w.txn(t, w.run, true, "DENY", "X") // created before the range started
	r := w.start(t, "RT-009", "RT-010")
	if r.Started.IsZero() {
		t.Fatal("no database start time")
	}
	saw := w.txn(t, w.run, true, "ALLOW", "GRANT_ALLOWS")
	res, err := w.svc.RecordResult(ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-009", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "exfil", Kind: "agent.call", Expect: deny, Observed: deny, Transaction: uid(saw)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != domain.Fail || res.Claimed != domain.Pass || !res.Steps[0].Mismatch || res.Steps[0].ObservedBy != domain.Server {
		t.Fatalf("result = %+v", res)
	}
	for name, id := range map[string]ids.UUID{
		"a real run's": w.txn(t, w.realRun, false, "DENY", "DESTINATION_NOT_GRANTED"),
		"a simulated transaction of a real agent's run": w.txn(t, w.realRun, true, "DENY", "DESTINATION_NOT_GRANTED"),
		"one from before the range":                     before, "an unknown one": ids.NewV7(),
	} {
		_, err := w.svc.RecordResult(ctx, app.RecordInput{
			Range: r.ID, Scenario: "RT-010", Digest: hexA, Verdict: domain.Pass,
			Steps: []domain.StepInput{{ID: "s", Kind: "agent.call", Expect: deny, Observed: deny, Transaction: uid(id)}},
		})
		if !errors.Is(err, app.ErrRecord) {
			t.Errorf("%s: err = %v, want RANGE_RECORD_INVALID", name, err)
		}
	}
	// The stored result reads back as recorded.
	got, err := w.svc.GetRange(ctx, r.ID)
	if err != nil || len(got.Results) != 1 || got.Results[0].Steps[0].Observed.Outcome != domain.OutcomeAllow ||
		got.Results[0].Steps[0].Claimed.Outcome != domain.OutcomeDeny || got.Results[0].Steps[0].Transaction == nil {
		t.Fatalf("read back: %+v, %v", got, err)
	}
	// Finishing adds the MISSING scenario; the database holds both rows.
	fin, err := w.svc.FinishRange(ctx, r.ID)
	if err != nil || fin.Counts != (domain.Counts{Fail: 1, Missing: 1}) {
		t.Fatalf("finish: %+v, %v", fin.Counts, err)
	}
	if _, err := w.svc.FinishRange(ctx, r.ID); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("second finish: %v", err)
	}
	if n := w.count(t, w.org, "SELECT count(*) FROM pc.redteam_results WHERE range_id = $1", r.ID); n != 2 {
		t.Fatalf("%d result rows, want 2", n)
	}
}

// Results are evidence: pc_app cannot update or delete them, a range
// changes once and forward, and a result lands only in a range that runs
// (or, as MISSING, in one that finished) for a scenario it declared.
func TestHR224_ResultsAreAppendOnlyAndRangesChangeOnce(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	ctx := w.as(td.RoleAgentOwner)
	r := w.start(t, "RT-001")
	blocked := domain.Expect{Outcome: domain.OutcomeBlocked}
	if _, err := w.svc.RecordResult(ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "s", Kind: "agent.call", Expect: blocked, Observed: blocked}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.RecordResult(ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Fail,
		Steps: []domain.StepInput{{ID: "s", Kind: "agent.call", Expect: blocked, Observed: domain.Expect{Outcome: domain.OutcomeAllow}}},
	}); !errors.Is(err, app.ErrRecorded) {
		t.Fatalf("a second result: %v", err)
	}
	for _, sql := range []string{
		"UPDATE pc.redteam_results SET verdict = 'FAIL'",
		"DELETE FROM pc.redteam_results",
		"UPDATE pc.redteam_runs SET runner_version = 'x'",
		"UPDATE pc.redteam_runs SET range_agent_id = scenario_set_digest::uuid",
		"DELETE FROM pc.redteam_runs",
	} {
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		}); err == nil {
			t.Errorf("%s: succeeded", sql)
		}
	}
	// A direct insert for an undeclared scenario or into a finished range fails.
	insert := `INSERT INTO pc.redteam_results (org_id, range_id, scenario_id, scenario_digest, suite, category, tier, verdict, observed_by)
		VALUES ($1, $2, $3, $4, 'platform', 'boundary', 'community', 'SKIPPED', 'NONE')`
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, insert, w.org, r.ID, "RT-099", hexA)
		return err
	}); err == nil {
		t.Error("a result for an undeclared scenario")
	}
	if _, err := w.svc.FinishRange(ctx, r.ID); err != nil {
		t.Fatal(err)
	}
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, insert, w.org, r.ID, "RT-001", hexA)
		return err
	}); err == nil {
		t.Error("a result recorded after the finish")
	}
	// The database refuses a range for a real agent, and an unfinished baseline.
	run := func(agent ids.UUID, baseline *ids.UUID) error {
		return w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest,
				scenarios, baseline_range_id) VALUES ($1, $2, $3, 'user:x', 'v', $4, $5::jsonb, $6)`,
				w.org, ids.NewV7(), agent, hexA, `[{"id":"RT-001","digest":"`+hexA+`","tier":"community","category":"boundary","suite":"coding-agent"}]`, baseline)
			return err
		})
	}
	if err := run(w.realAgent, nil); err == nil {
		t.Error("a range for a real agent")
	}
	if err := run(w.rangeAgent, uid(r.ID)); err != nil {
		t.Errorf("a range with a finished baseline: %v", err)
	}
	r2 := w.start(t, "RT-001")
	if err := run(w.rangeAgent, uid(r2.ID)); err == nil {
		t.Error("a range with a running baseline")
	}
}

// TestHR224_RangesRunOnlyForRangeAgents: StartRange for a real agent is
// refused before it reaches the database.
func TestHR224_RangesRunOnlyForRangeAgents(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	_, err := w.svc.StartRange(w.as(td.RoleAgentOwner), app.StartInput{Agent: w.realAgent, Scenarios: []domain.Scenario{decl("RT-001")}, RunnerVersion: "t"})
	if !errors.Is(err, app.ErrNotRange) {
		t.Fatalf("a real agent: %v", err)
	}
}

// TestHR224_StaleRangesAreAbandonedAfter24Hours (the janitor pattern): a
// range running for over 24 hours is abandoned once, audited, and takes no
// more results; a fresh one is left alone.
func TestHR224_StaleRangesAreAbandonedAfter24Hours(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	ctx := w.as(td.RoleAgentOwner)
	fresh := w.start(t, "RT-001")
	// The migrator may insert a range that started 25 hours ago; the app cannot.
	old := domain.Range{ID: ids.NewV7()}
	if err := w.admin.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest,
			scenarios, started_at) VALUES ($1, $2, $3, 'user:x', 'v', $4, $5::jsonb, now() - interval '25 hours')`,
			w.org, old.ID, w.rangeAgent, hexA, `[{"id":"RT-001","digest":"`+hexA+`","tier":"community","category":"boundary","suite":"coding-agent"}]`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	n, err := pgranges.Abandoner{Pool: w.pool}.AbandonStale(ctx, w.org)
	if err != nil || n != 1 {
		t.Fatalf("abandoned %d, %v, want 1", n, err)
	}
	if n, err := (pgranges.Abandoner{Pool: w.pool}).AbandonStale(ctx, w.org); err != nil || n != 0 {
		t.Fatalf("second sweep: %d, %v", n, err)
	}
	got, err := w.svc.GetRange(ctx, old.ID)
	if err != nil || got.Range.State != domain.Abandoned || got.Range.Finished == nil {
		t.Fatalf("old range: %+v, %v", got.Range, err)
	}
	if g, _ := w.svc.GetRange(ctx, fresh.ID); g.Range.State != domain.Running {
		t.Fatalf("fresh range %s", g.Range.State)
	}
	blocked := domain.Expect{Outcome: domain.OutcomeBlocked}
	if _, err := w.svc.RecordResult(ctx, app.RecordInput{
		Range: old.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "s", Kind: "agent.call", Expect: blocked, Observed: blocked}},
	}); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("a result in an abandoned range: %v", err)
	}
	if n := w.count(t, w.org, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.redteam.range_abandoned'"); n != 1 {
		t.Errorf("%d abandon audit events, want 1", n)
	}
}

// TestTenancy_redteam_runs: another org sees none of a range, whether by
// the service, a list or the tables, and cannot write one into this org.
func TestTenancy_redteam_runs(t *testing.T) {
	d := dbtest.New(t)
	w, them := newWorld(t, d), newWorld(t, d)
	r := w.start(t, "RT-001")
	other := them.as(td.RoleAgentOwner, td.RoleSecurityAdmin, td.RoleAuditor)
	if _, err := them.svc.GetRange(other, r.ID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := them.svc.FinishRange(other, r.ID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("finish: %v", err)
	}
	if _, err := them.svc.RecordResult(other, app.RecordInput{Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Skipped}); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("record: %v", err)
	}
	if _, err := them.svc.ExportAssuranceReport(other, r.ID); err == nil {
		t.Error("export of another org's range")
	}
	for name, agent := range map[string]*ids.UUID{"all": nil, "their agent": &w.rangeAgent} {
		if p, err := them.svc.ListRanges(other, agent, page.Request{Size: 10}); err != nil || len(p.Items) != 0 {
			t.Errorf("list %s: %d, %v", name, len(p.Items), err)
		}
	}
	if _, err := them.svc.StartRange(other, app.StartInput{Agent: w.rangeAgent, Scenarios: []domain.Scenario{decl("RT-001")}, RunnerVersion: "t"}); !errors.Is(err, app.ErrAgentMissing) {
		t.Errorf("a range for their agent: %v", err)
	}
	if n := them.count(t, them.org, "SELECT count(*) FROM pc.redteam_runs WHERE id = $1", r.ID); n != 0 {
		t.Errorf("their tenant reads %d of our ranges", n)
	}
	err := them.pool.InTenantTx(context.Background(), them.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest, scenarios)
			VALUES ($1, $2, $3, 'user:x', 'v', $4, '[{}]')`, w.org, ids.NewV7(), w.rangeAgent, hexA)
		return err
	})
	if err == nil {
		t.Error("a range written into another org")
	}
	if n := w.count(t, w.org, "SELECT count(*) FROM pc.redteam_runs WHERE id = $1 AND state = 'RUNNING'", r.ID); n != 1 {
		t.Error("our range changed")
	}
}

// TestTenancy_redteam_results: results are visible to their org only.
func TestTenancy_redteam_results(t *testing.T) {
	d := dbtest.New(t)
	w, them := newWorld(t, d), newWorld(t, d)
	r := w.start(t, "RT-001")
	blocked := domain.Expect{Outcome: domain.OutcomeBlocked}
	if _, err := w.svc.RecordResult(w.as(td.RoleAgentOwner), app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "s", Kind: "agent.call", Expect: blocked, Observed: blocked}},
	}); err != nil {
		t.Fatal(err)
	}
	if n := them.count(t, them.org, "SELECT count(*) FROM pc.redteam_results WHERE range_id = $1", r.ID); n != 0 {
		t.Errorf("their tenant reads %d of our results", n)
	}
	err := them.pool.InTenantTx(context.Background(), them.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.redteam_results (org_id, range_id, scenario_id, scenario_digest, suite, category, tier, verdict, observed_by)
			VALUES ($1, $2, 'RT-002', $3, 'platform', 'boundary', 'community', 'SKIPPED', 'NONE')`, w.org, r.ID, hexA)
		return err
	})
	if err == nil {
		t.Error("a result written into another org")
	}
	if n := w.count(t, w.org, "SELECT count(*) FROM pc.redteam_results WHERE range_id = $1", r.ID); n != 1 {
		t.Errorf("our org holds %d results, want 1", n)
	}
}

// A role without redteam.run reads but cannot write; a role with neither
// finds nothing.
func TestRangePermissionsOnTheRealStore(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	r := w.start(t, "RT-001")
	auditor, viewer := w.as(td.RoleAuditor), w.as(td.RoleViewer)
	if _, err := w.svc.GetRange(auditor, r.ID); err != nil {
		t.Fatalf("auditor get: %v", err)
	}
	if _, err := w.svc.FinishRange(auditor, r.ID); err == nil || errors.Is(err, app.ErrNotFound) {
		t.Fatalf("auditor finish: %v, want permission denied", err)
	}
	if _, err := w.svc.GetRange(viewer, r.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("viewer get: %v", err)
	}
}
