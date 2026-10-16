// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The core's tests (G0 M11 part 2 D5–D10, D54–D57): HR-270 (the execution
// identity), HR-271 (ceiling-bounded issuance), HR-272 (enabling through
// distinct eligible confirmers), HR-273 (a confirmer losing a permission
// voids the ceiling), HR-274 (attribution and inventory), T-120 (ceiling
// abuse or self-widening) and T-121 (identity misuse).

type editions struct{}

func (editions) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Team}, nil
}

type operations struct{}

// spending names operations that take a money parameter (a test sets it
// after enabling, so issuance meets a spending operation validation never
// saw).
var spending = map[string]bool{}

func (operations) Active(_ context.Context, _ ids.OrgID, op string) (*defs.Definition, error) {
	d := &defs.Definition{Operation: op, Reversibility: defs.Reversible}
	if spending[op] {
		d.Params = map[string]defs.ParamSpec{"amount": {Type: defs.TypeMoney}}
	}
	return d, nil
}

type testGate struct{ ok bool }

func (g *testGate) Passed(context.Context, pgx.Tx, ids.UUID, []byte) (ids.UUID, bool, error) {
	return ids.NewV7(), g.ok, nil
}

// verified is assurance's rollout evidence, always shown (D36).
type verified struct{}

func (verified) Verified(context.Context, pgx.Tx, ids.UUID, ids.UUID) (bool, []string, error) {
	return true, nil, nil
}

type person struct {
	id, key, session ids.UUID
	page, cli        context.Context
}

type env struct {
	t               *testing.T
	pool            *db.Pool
	org             ids.OrgID
	team, envID     ids.UUID
	agent, other    ids.UUID
	svc             *autoapp.Service
	grants          *grantsapp.Service
	runs            *runsapp.Service
	gate            *testGate
	db              *dbtest.DB
	alice, bob, cat person
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) execErr(sql string, args ...any) error {
	return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (e *env) agentRow(name string) ids.UUID {
	id := ids.NewV7()
	e.exec(`INSERT INTO pc.agents (org_id, id, name, state, team_id, environment_id, owner_user_id, execution_context,
		claimed_at, created_by) VALUES ($1, $2, $3, 'CLAIMED', $4, $5, $6, 'ci', now(), 'test')`, e.org, id, name, e.team, e.envID, e.alice.id)
	return id
}

func (e *env) person(name string, roles ...td.RoleName) person {
	e.t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	e.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, p.id, name)
	e.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, p.key, p.id, secret[:16], secret)
	e.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, e.org, p.session, p.id, secret)
	var bs []td.Binding
	for _, r := range roles {
		e.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			e.org, ids.NewV7(), string(r), p.id)
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}})
	}
	sub := td.Subject{Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id}, Bindings: bs}
	p.page = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredBrowserSession, Session: p.session})
	p.cli = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredAccessToken, Session: ids.NewV7()})
	return p
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{t: t, pool: d.AppPool(t), db: d, org: ids.New[ids.Org](), team: ids.NewV7(), envID: ids.NewV7(), gate: &testGate{ok: true}}
	e.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", e.org)
	e.exec("INSERT INTO pc.org_containment (org_id) VALUES ($1)", e.org)
	e.exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'ops', 'Ops')", e.org, e.team)
	e.exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')",
		e.org, e.envID, e.team)
	e.alice = e.person("alice", td.RoleAutomationAuthor, td.RoleOrgAdmin)
	e.bob = e.person("bob", td.RoleAutomationPublisher, td.RoleGrantIssuer, td.RoleRunLauncher)
	e.cat = e.person("cat", td.RoleAutomationPublisher, td.RoleGrantIssuer, td.RoleRunLauncher)
	e.agent, e.other = e.agentRow("support"), e.agentRow("billing")
	gstore := &grantspg.Store{Pool: e.pool}
	e.grants = &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: operations{}, Authz: grantsapp.SubjectAuthorizer{}, Clock: clock.System{},
		Listing: gstore, Store: gstore,
	}
	e.runs = runsapp.New(e.pool).WithGrants(gstore)
	ch := changes.New(e.pool, "https://pc.example.test")
	e.svc = &autoapp.Service{
		Pool: e.pool, Clock: clock.System{}, Changes: ch, Grants: e.grants, Runs: e.runs, Editions: editions{},
		Operations: operations{}, TestGate: e.gate, Rollout: verified{}, Failures: &failures.Sink{},
	}
	e.svc.RegisterChanges()
	e.grants.Ceilings = e.svc
	e.runs.WithAutomationRuns(e.svc)
	return e
}

func (e *env) definition(perDayGrants int) string {
	review := time.Now().UTC().AddDate(0, 0, 30).Format(time.DateOnly)
	return fmt.Sprintf(`
apiVersion: automations.pantherclaw.dev/v1
kind: Automation
purpose: Refund small tickets.
work_kind: AGENT_WORK
review_by: "%s"
when:
  manual:
    params:
      ticket:
        type: string
        pattern: "T-[0-9]{1,10}"
authority:
  principal: self
  ceiling:
    agents: [%s]
    bounds:
      operations: [payments.refund.create]
    per_grant:
      ttl: 1h
    per_day:
      grants: %d
      runs: 5
do:
  - id: launch
    step: launch_run
    with:
      agent: %s
      task_ref: "ticket {{params.ticket}}"
  - id: wait
    step: wait_run
    with:
      step: launch
    timeout: 2h
finish_when:
  - step: wait
    condition: RUN_ENDED
`, review, e.agent, perDayGrants, e.agent)
}

// enabled creates an automation and enables a validated, tested version
// with bob's and cat's confirmations.
func (e *env) enabled(name string, rollout autodomain.Rollout, perDay int) (autoapp.Automation, autoapp.Version) {
	e.t.Helper()
	a, err := e.svc.CreateAutomation(e.alice.cli, name, "Refund small tickets.", autodomain.WorkAgent, e.alice.id)
	if err != nil {
		e.t.Fatal(err)
	}
	v, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(perDay)))
	if err != nil {
		e.t.Fatal(err)
	}
	v, ok, err := e.svc.ValidateVersion(e.alice.cli, v.ID)
	if err != nil || !ok {
		e.t.Fatalf("validate: %v %+v", err, v.Findings)
	}
	// FULL comes through COHORT and a ROLLOUT (D91).
	steps := []autodomain.Rollout{rollout}
	if rollout == autodomain.RolloutFull {
		steps = []autodomain.Rollout{autodomain.RolloutCohort, autodomain.RolloutFull}
	}
	for _, r := range steps {
		var cohort []ids.UUID
		if r == autodomain.RolloutCohort {
			cohort = []ids.UUID{e.agent}
		}
		en, err := e.svc.RequestEnable(e.alice.cli, v.ID, r, cohort, ids.UUID{})
		if err != nil {
			e.t.Fatal(err)
		}
		for _, p := range []person{e.bob, e.cat}[:en.Required] {
			if _, err := e.svc.Changes.Confirm(p.page, en.Request.ID, e.sign(p, en.Request)); err != nil {
				e.t.Fatalf("confirm: %v", err)
			}
		}
	}
	a, err = e.svc.GetAutomation(e.alice.cli, a.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return a, v
}

// sign is p's BINDING ceremony over the request's binding, as the page
// starts it.
func (e *env) sign(p person, r changes.Request) changes.Assertion {
	e.t.Helper()
	cer := ids.NewV7()
	e.exec(`DELETE FROM pc.webauthn_ceremonies WHERE org_id = $1 AND user_id = $2 AND change_request_id = $3 AND consumed_at IS NULL`,
		e.org, p.id, r.ID)
	e.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, e.org, cer, p.session, p.id, r.Binding[:], r.ID)
	return changes.Assertion{Ceremony: cer, Credential: p.key}
}

// execution records a manual trigger of a and its execution, as the
// triggers stream and the engine do: a grant names a real execution
// (00142). The execution is LIVE when a has a ceiling (a LIVE execution
// names one), else SHADOW; issuance reads only the request's Live.
func (e *env) execution(a autoapp.Automation, v autoapp.Version) (exec, trig ids.UUID) {
	e.t.Helper()
	exec, trig = ids.NewV7(), ids.NewV7()
	var ceiling *ids.UUID
	mode := "SHADOW" // a LIVE execution names its ceiling
	if a.Ceiling != nil {
		ceiling, mode = &a.Ceiling.ID, "LIVE"
	}
	e.exec(`INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref, authenticity,
		params, root_trigger_id, state, occurred_at) VALUES ($1, $2, $3, $4, 'MANUAL', 'LIVE', 'manual:test', 'USER_SESSION',
		'{}', $2, 'ACCEPTED', now())`, e.org, trig, a.ID, v.ID)
	e.exec(`INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode, ceiling_id,
		service_account_id, principal_sa_id, trigger_kind, occurred_at, root_trigger_id, deadline_at)
		VALUES ($1, $2, $3, $4, $5, $8, $6, $7, $7, 'MANUAL', now(), $5, now() + interval '1 hour')`,
		e.org, exec, a.ID, v.ID, trig, ceiling, a.ServiceAccount, mode)
	return exec, trig
}

func (e *env) issue(a autoapp.Automation, v autoapp.Version, mod func(*grantsapp.AutomationIssue)) (gdomain.Grant, error) {
	exec, trig := e.execution(a, v)
	in := grantsapp.AutomationIssue{
		Org: e.org, Automation: a.ID, Version: v.ID, Execution: exec, Trigger: trig,
		ServiceAccount: a.ServiceAccount, AgentID: e.agent, Live: true, TaskRef: "ticket T-1",
		Principal: gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: a.ServiceAccount},
		Bounds:    gdomain.Bounds{Operations: &gdomain.Ops{"payments.refund.create"}},
	}
	if a.Ceiling != nil {
		in.Ceiling = a.Ceiling.ID
	}
	if mod != nil {
		mod(&in)
	}
	var g gdomain.Grant
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		g, err = e.grants.IssueForAutomationTx(ctx, tx, in)
		return err
	})
	return g, err
}

func reason(err error) string { return pcerr.ReasonOf(err) }

// TestHR270_ExecutionIdentityHoldsNoCredentials: an automation acts only
// as its own service account, which the service-account and role APIs
// never edit, re-enable or give keys or bindings, and the database refuses
// the same rows.
func TestHR270_ExecutionIdentityHoldsNoCredentials(t *testing.T) {
	e := newEnv(t)
	a, err := e.svc.CreateAutomation(e.alice.cli, "refunds", "Refund small tickets.", autodomain.WorkAgent, e.alice.id)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count("SELECT count(*) FROM pc.service_accounts WHERE org_id = $1 AND id = $2 AND automation_id = $3 AND name = 'automation-refunds'",
		e.org, a.ServiceAccount, a.ID); n != 1 {
		t.Fatalf("identity rows %d", n)
	}
	sas := tapp.NewServiceAccounts(e.pool, credential.EnvTest)
	sa, err := ids.FromUUID[td.ServiceAccount](a.ServiceAccount)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk, _ := jose.JSONWebKey{Key: pub}.MarshalJSON()
	desc := "changed"
	for name, call := range map[string]func() error{
		"api key": func() error {
			_, _, err := sas.CreateAPIKey(e.alice.cli, sa, "k", []td.Permission{td.PermAgentRead}, 0)
			return err
		},
		"key":       func() error { _, err := sas.AddKey(e.alice.cli, sa, assertion.EdDSA, string(jwk), 0); return err },
		"update":    func() error { _, err := sas.Update(e.alice.cli, sa, &desc); return err },
		"set state": func() error { _, err := sas.SetState(e.alice.cli, sa, td.Disabled); return err },
		"binding": func() error {
			_, _, err := tapp.NewAccess(e.pool, nil).CreateRoleBinding(e.alice.cli, td.RoleViewer,
				td.PrincipalRef{Kind: td.KindServiceAccount, ID: a.ServiceAccount}, td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()})
			return err
		},
	} {
		if err := call(); reason(err) != "AUTOMATION_IDENTITY" {
			t.Errorf("%s: %v, want AUTOMATION_IDENTITY", name, err)
		}
	}
	if _, err := sas.Create(e.alice.cli, "automation-fake", ""); reason(err) != "AUTOMATION_NAME_RESERVED" {
		t.Errorf("an ordinary automation-* account: %v", err)
	}
	// The database refuses the same rows (backstop).
	for name, sql := range map[string]string{
		"binding": `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by)
			VALUES ($1, gen_random_uuid(), 'viewer', $2, 'ORG', 'test')`,
		"api key": `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at)
			VALUES ($1, gen_random_uuid(), $2, 'k', decode(repeat('ab', 32), 'hex'), 'h', '{agent.read}', 'test', now() + interval '1 day')`,
		"re-assign": `UPDATE pc.service_accounts SET automation_id = NULL WHERE org_id = $1 AND id = $2`,
	} {
		// pc_app may not even UPDATE automation_id; the guard refuses any
		// other role.
		if err := e.execErr(sql, e.org, a.ServiceAccount); err == nil ||
			(!strings.Contains(err.Error(), "AUTOMATION_IDENTITY") && !strings.Contains(err.Error(), "permission denied")) {
			t.Errorf("database %s: %v", name, err)
		}
	}
}

// TestHR272_EnablingNeedsDistinctEligibleConfirmers: a cohort or full
// enabling needs two eligible people (each holding automation.publish and
// every confirmer permission where the version acts) with distinct keys;
// the author's role alone qualifies nobody; an untested version is refused.
func TestHR272_EnablingNeedsDistinctEligibleConfirmers(t *testing.T) {
	e := newEnv(t)
	a, err := e.svc.CreateAutomation(e.alice.cli, "refunds", "Refund small tickets.", autodomain.WorkAgent, e.alice.id)
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(5)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutShadow, nil, ids.UUID{}); reason(err) != "VERSION_STATE" {
		t.Errorf("an unvalidated version: %v", err)
	}
	if v, _, err = e.svc.ValidateVersion(e.alice.cli, v.ID); err != nil || v.State != autodomain.VersionValidated || v.Summary == "" {
		t.Fatalf("validate: %v %s", err, v.State)
	}
	cohort := []ids.UUID{e.agent}
	e.gate.ok = false
	if _, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutCohort, cohort, ids.UUID{}); reason(err) != "VERSION_UNTESTED" {
		t.Errorf("an untested cohort rollout: %v", err)
	}
	e.gate.ok = true
	if _, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutFull, nil, ids.UUID{}); reason(err) != "FULL_NEEDS_COHORT" {
		t.Errorf("a first enabling straight to FULL: %v", err)
	}
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutCohort, cohort, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	if en.Required != 2 {
		t.Fatalf("required %d, want 2 (two eligible people)", en.Required)
	}
	if _, err := e.svc.RequestEnable(e.bob.cli, v.ID, autodomain.RolloutCohort, cohort, ids.UUID{}); err == nil {
		t.Error("a publisher asked for an enabling without automation.manage")
	}
	if _, err := e.svc.Changes.Confirm(e.alice.page, en.Request.ID, e.sign(e.alice, en.Request)); reason(err) != "NOT_ELIGIBLE" {
		t.Errorf("the author confirmed: %v", err)
	}
	if _, err := e.svc.Changes.Confirm(e.bob.cli, en.Request.ID, e.sign(e.bob, en.Request)); reason(err) != "BROWSER_SESSION_REQUIRED" {
		t.Errorf("a confirmation outside the page: %v", err)
	}
	r, err := e.svc.Changes.Confirm(e.bob.page, en.Request.ID, e.sign(e.bob, en.Request))
	if err != nil || r.State != changes.StatePending {
		t.Fatalf("bob: %v %s", err, r.State)
	}
	if _, err := e.svc.Changes.Confirm(e.bob.page, en.Request.ID, e.sign(e.bob, en.Request)); reason(err) != "SAME_PERSON" {
		t.Errorf("bob twice: %v", err)
	}
	if got, _ := e.svc.GetAutomation(e.alice.cli, a.ID); got.State != autodomain.StateDraft || got.Ceiling != nil {
		t.Fatalf("enabled after one confirmation: %s", got.State)
	}
	if r, err = e.svc.Changes.Confirm(e.cat.page, en.Request.ID, e.sign(e.cat, en.Request)); err != nil || r.State != changes.StateApproved {
		t.Fatalf("cat: %v %s", err, r.State)
	}
	got, err := e.svc.GetAutomation(e.alice.cli, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != autodomain.StateActive || got.Rollout != autodomain.RolloutCohort || got.Ceiling == nil ||
		!slices.Equal(got.Ceiling.ApprovedBy, []ids.UUID{e.bob.id, e.cat.id}) {
		t.Fatalf("after enabling: %+v %+v", got, got.Ceiling)
	}
	if !got.Ceiling.ReviewBy.Before(time.Now().Add(autodomain.MaxReviewWindow)) {
		t.Errorf("review date %s beyond 90 days", got.Ceiling.ReviewBy)
	}
	// An automation never changes its own definition: a published version
	// is immutable in the database.
	if err := e.execErr("UPDATE pc.automation_versions SET definition = '{}' WHERE org_id = $1 AND id = $2", e.org, v.ID); err == nil {
		t.Error("a published definition changed")
	}
}

// TestHR271_IssuanceStaysInsideTheCeiling: the engine's issuance makes a
// grant whose grantor is the automation's identity under its ceiling, for
// at most 24 hours; anything outside the ceiling, past the daily cap or in
// a dry run writes nothing; the database refuses a service-account root
// grant without a ceiling, and RPC Issue stays human only.
func TestHR271_IssuanceStaysInsideTheCeiling(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutFull, 2)
	g, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if g.Grantor != (gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: a.ServiceAccount}) || g.Ceiling != a.Ceiling.ID ||
		time.Until(g.ExpiresAt) > time.Hour+time.Minute {
		t.Fatalf("issued %+v", g)
	}
	if n := e.count("SELECT count(*) FROM pc.grants WHERE org_id = $1 AND ceiling_id = $2 AND grantor_kind = 'service_account'", e.org, a.Ceiling.ID); n != 1 {
		t.Fatalf("ceiling grants %d", n)
	}
	before := e.count("SELECT count(*) FROM pc.grants WHERE org_id = $1", e.org)
	for name, mod := range map[string]func(*grantsapp.AutomationIssue){
		"another agent":     func(in *grantsapp.AutomationIssue) { in.AgentID = e.other },
		"another operation": func(in *grantsapp.AutomationIssue) { in.Bounds.Operations = &gdomain.Ops{"payments.charge.create"} },
		"another principal": func(in *grantsapp.AutomationIssue) {
			in.Principal = gdomain.Principal{Kind: gdomain.PrincipalUser, ID: e.bob.id}
		},
		"shadow":           func(in *grantsapp.AutomationIssue) { in.Live = false },
		"another identity": func(in *grantsapp.AutomationIssue) { in.ServiceAccount = ids.NewV7() },
	} {
		if _, err := e.issue(a, v, mod); err == nil {
			t.Errorf("%s: issued", name)
		}
	}
	if _, err := e.issue(a, v, func(in *grantsapp.AutomationIssue) { in.DryRun = true }); err != nil {
		t.Errorf("dry run: %v", err)
	}
	if after := e.count("SELECT count(*) FROM pc.grants WHERE org_id = $1", e.org); after != before {
		t.Fatalf("refused or dry-run issuance wrote %d grants", after-before)
	}
	if _, err := e.issue(a, v, nil); err != nil {
		t.Fatalf("second grant: %v", err)
	}
	if _, err := e.issue(a, v, nil); reason(err) != "USAGE_EXCEEDED" {
		t.Errorf("third grant of a 2-a-day ceiling: %v", err)
	}
	if n := e.count("SELECT coalesce(sum(grants), 0)::int FROM pc.automation_usage WHERE org_id = $1 AND automation_id = $2", e.org, a.ID); n != 2 {
		t.Errorf("usage %d after a refused third grant", n)
	}
	err = e.execErr(`INSERT INTO pc.grants (org_id, id, agent_id, principal_sa_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis) VALUES ($1, gen_random_uuid(), $2, $3, $4, 0, 1, 'service_account', $3, 'x')`,
		e.org, e.agent, a.ServiceAccount, e.envID)
	if err == nil || !strings.Contains(err.Error(), "grants_root_grantor") {
		t.Errorf("a service-account root grant without a ceiling: %v", err)
	}
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: a.ServiceAccount},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAPIKey})
	if _, err := e.grants.Issue(sa, grantsapp.IssueRequest{AgentID: e.agent, ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Error("a service account issued through Issue")
	}
}

// TestHR273_ConfirmerLosingPermissionVoidsTheCeiling: when an approver no
// longer holds what the version needs, issuance refuses CEILING_VOID and
// VoidCeiling voids the ceiling and pauses the automation.
func TestHR273_ConfirmerLosingPermissionVoidsTheCeiling(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutFull, 5)
	e.exec("DELETE FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND role = 'grant_issuer'", e.org, e.cat.id)
	if _, err := e.issue(a, v, nil); reason(err) != "CEILING_VOID" {
		t.Fatalf("after cat lost grant.issue: %v", err)
	}
	if n := e.count("SELECT count(*) FROM pc.grants WHERE org_id = $1", e.org); n != 0 {
		t.Fatalf("%d grants written by a refused issuance", n)
	}
	if err := e.svc.VoidCeiling(context.Background(), e.org, a.Ceiling.ID, autoapp.ReasonApproverPermission); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.GetAutomation(e.alice.cli, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != autodomain.StatePaused || got.PauseReason != autodomain.PauseCeilingVoid || got.Ceiling != nil {
		t.Fatalf("after voiding: %s %s %+v", got.State, got.PauseReason, got.Ceiling)
	}
	if _, _, err := e.svc.ResumeAutomation(e.alice.cli, a.ID); reason(err) != "AUTHORITY_CHANGED" {
		t.Errorf("resumed without authority: %v", err)
	}
	// The sweep finds the same on its own.
	b, bv := e.enabled("refunds2", autodomain.RolloutFull, 5)
	_ = bv
	e.exec("DELETE FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND role = 'run_launcher'", e.org, e.bob.id)
	out, err := e.svc.SweepOrg(context.Background(), e.org)
	if err != nil || out.Voided != 1 {
		t.Fatalf("sweep: %+v %v", out, err)
	}
	if got, _ := e.svc.GetAutomation(e.alice.cli, b.ID); got.State != autodomain.StatePaused {
		t.Errorf("the sweep left %s", got.State)
	}
}

// TestHR274_AutomationRecordsCarryAttributionAndInventory: the grant's
// audit record names the automation, version, execution and trigger, and
// the automation appears in the inventory.
func TestHR274_AutomationRecordsCarryAttributionAndInventory(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutFull, 5)
	var exec, trigger ids.UUID
	if _, err := e.issue(a, v, func(in *grantsapp.AutomationIssue) { exec, trigger = in.Execution, in.Trigger }); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{a.ID.String(), v.ID.String(), exec.String(), trigger.String(), a.Ceiling.ID.String()} {
		if n := e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.grant.issued'
			AND convert_from(body, 'UTF8') LIKE '%' || $2 || '%'`, e.org, want); n != 1 {
			t.Errorf("grant.issued does not name %s", want)
		}
	}
	xs, note, err := e.svc.Identities(e.alice.cli)
	if err != nil || note != "" || len(xs) != 1 || xs[0].Automation != a.ID || xs[0].ServiceAccount != a.ServiceAccount ||
		xs[0].ActiveGrants != 1 || xs[0].CeilingAgents != 1 {
		t.Fatalf("inventory %+v %q %v", xs, note, err)
	}
	viewer := e.person("vic", td.RoleDeveloper)
	if xs, note, _ := e.svc.Identities(viewer.cli); len(xs) != 0 || note == "" {
		t.Errorf("an inventory without automation.read: %+v", xs)
	}
}

// TestT120_NoSelfWidening: a grant an automation issued is narrowed or
// revoked by people, never widened; it binds only to its execution's run;
// a new definition needs a new version and a new ceremony.
func TestT120_NoSelfWidening(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutFull, 5)
	g, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	wider := gdomain.Bounds{Operations: &gdomain.Ops{"payments.*"}}
	_, _, err = e.grants.Revise(e.bob.cli, grantsapp.ReviseRequest{ID: g.ID, Revision: g.Revision, Bounds: wider})
	if reason(err) != "CEILING_GRANT" {
		t.Errorf("widening an automation's grant: %v", err)
	}
	// A person's run cannot use the automation's grant (D56).
	gid := g.ID.UUID()
	if _, err := e.runs.StartRun(e.bob.cli, runsapp.StartInput{AgentID: e.agent, GrantID: &gid}); err == nil {
		t.Error("a person's run bound an automation's grant")
	}
	// The execution's own run binds it, launched by the identity.
	var run runsapp.Run
	err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		run, err = e.runs.StartForAutomationTx(ctx, tx, runsapp.AutomationStart{
			Org: e.org, Automation: a.ID, Version: v.ID, Execution: g.Execution, ServiceAccount: a.ServiceAccount,
			AgentID: e.agent, GrantID: gid, Principal: g.Principal, TaskRef: "ticket T-1",
		})
		return err
	})
	if err != nil || run.PrincipalSource != runsapp.SourceAutomation || run.GrantID == nil || *run.GrantID != gid {
		t.Fatalf("the execution's run: %+v %v", run, err)
	}
	// Changing the definition means a new version and a new ceremony.
	if _, err := e.svc.UpdateDraftVersion(e.alice.cli, v.ID, []byte(e.definition(50)), v.Digest); reason(err) != "VERSION_STATE" {
		t.Errorf("edited a published version: %v", err)
	}
	v2, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(50)))
	if err != nil {
		t.Fatal(err)
	}
	if v2.State != autodomain.VersionDraft {
		t.Errorf("a new version starts %s", v2.State)
	}
	if got, _ := e.svc.GetAutomation(e.alice.cli, a.ID); got.EnabledVersion != v.ID {
		t.Errorf("a draft changed the enabled version")
	}
}

// TestT121_IdentityMisuse: the database ties a ceiling grant to its
// automation's identity, and retiring disables the identity for good.
func TestT121_IdentityMisuse(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutFull, 5)
	other, err := tapp.NewServiceAccounts(e.pool, credential.EnvTest).Create(e.alice.cli, "robot", "")
	if err != nil {
		t.Fatal(err)
	}
	err = e.execErr(`INSERT INTO pc.grants (org_id, id, agent_id, principal_sa_id, environment_id, depth, current_revision,
		grantor_kind, grantor_id, basis, ceiling_id) VALUES ($1, gen_random_uuid(), $2, $3, $4, 0, 1, 'service_account', $3, 'x', $5)`,
		e.org, e.agent, other.ID.UUID(), e.envID, a.Ceiling.ID)
	if err == nil || !strings.Contains(err.Error(), "CEILING_GRANTOR") {
		t.Errorf("another account issued under the ceiling: %v", err)
	}
	if _, _, err := e.svc.RetireAutomation(e.alice.cli, a.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if n := e.count("SELECT count(*) FROM pc.service_accounts WHERE org_id = $1 AND id = $2 AND state = 'DISABLED'", e.org, a.ServiceAccount); n != 1 {
		t.Error("retiring left the identity enabled")
	}
	if err := e.execErr("UPDATE pc.service_accounts SET state = 'ACTIVE' WHERE org_id = $1 AND id = $2", e.org, a.ServiceAccount); err == nil {
		t.Error("a retired automation's identity was re-enabled")
	}
	if _, _, err := e.svc.ResumeAutomation(e.alice.cli, a.ID); !errors.Is(err, autoapp.ErrState) {
		t.Errorf("resumed a retired automation: %v", err)
	}
}

// TestD14_PauserPausesEveryAutomation: the kill switch's Pauser pauses
// every ACTIVE automation in its transaction and returns them.
func TestD14_PauserPausesEveryAutomation(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutFull, 5)
	var paused []ids.UUID
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		paused, err = e.svc.Pause(ctx, tx.Pgx(), e.org, autodomain.PauseSelector{All: true}, autodomain.PauseKillSwitch)
		return err
	})
	if err != nil || !slices.Equal(paused, []ids.UUID{a.ID}) {
		t.Fatalf("paused %v %v", paused, err)
	}
	if got, _ := e.svc.GetAutomation(e.alice.cli, a.ID); got.PauseReason != autodomain.PauseKillSwitch {
		t.Errorf("pause reason %s", got.PauseReason)
	}
}
