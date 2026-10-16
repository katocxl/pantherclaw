// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// TestE2E_M11_GovernedAutomations is D49's governed-automations exit
// scenario (G0 M11 part 2). What runs where (D96, D117): the real e2e
// server (Community) serves people, the change pages, the gateway and
// workload tokens; the Business automations half runs in-process on the
// same database with the real services (autoStack).
func TestE2E_M11_GovernedAutomations(t *testing.T) {
	r := startReflex(t)
	s, ctx := r.s, context.Background()
	a := startAutomations(t, r)

	// People: alice authors the automation and owns it; bob and carol
	// publish automations, issue grants and launch runs, so they may
	// confirm its enabling (D6, D8).
	for _, role := range []string{"automation_author", "automation_operator"} {
		if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", r.aliceID.String()); code != 0 &&
			!strings.Contains(e, "ROLE_BINDING_EXISTS") {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	bob := a.confirmer(t, "bob")
	alice := signInWithKey(t, s, r.people, "alice", "alice@example.test")
	aliceCtx := a.person(r.aliceID, td.RoleAutomationAuthor, td.RoleAutomationOperator, td.RoleSecurityAdmin)

	// 1. An event source, activated with a step-up of alice's key (D19).
	created, err := a.sources.CreateEventSource(aliceCtx, endpoints.NewSource{Name: "tickets", Types: []string{"ticket.created"}})
	if err != nil {
		t.Fatalf("CreateEventSource: %v", err)
	}
	source := created.Source.ID
	if code := a.signedEvent(t, source, created.Secret, "msg-inactive", `{"type":"ticket.created","ref":"T-0"}`); code != http.StatusUnauthorized {
		t.Fatalf("an event to an inactive source: %d", code)
	}
	if _, err := a.sources.ActivateEventSource(aliceCtx, source, &stepup.StepUp{Credential: a.key(t, r.aliceID), At: time.Now()}); err != nil {
		t.Fatalf("ActivateEventSource: %v", err)
	}
	_ = alice

	// 2. The automation from bounded_task_launch: inbound ticket.created,
	// refunds on the mock payments connection for one agent, at most USD 50
	// per grant and 5 grants a day; the runner's refund call is added to the
	// rendered draft (D117).
	raw, cases, err := templates.Render("bounded_task_launch", map[string]string{
		"review_by": time.Now().AddDate(0, 0, 60).Format(time.DateOnly), "source": source.String(),
		"event_type": "ticket.created", "agent": r.agent.String(), "operations": "payments.refund.create",
		"confirm_operation": "payments.refund.create", "budget_per_run": "50.00", "budget_per_day": "250.00",
		"runs_per_day": "5",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	doc := a.withRefund(t, raw, "25.00")
	auto, err := a.core.CreateAutomation(aliceCtx, "ticket-refunds", "Refund duplicate ticket charges.", autodomain.WorkAgent, r.aliceID)
	if err != nil {
		t.Fatalf("CreateAutomation: %v", err)
	}
	v, err := a.core.CreateDraftVersion(aliceCtx, auto.ID, doc)
	if err != nil {
		t.Fatalf("CreateDraftVersion: %v", err)
	}
	if _, ok, err := a.core.ValidateVersion(aliceCtx, v.ID); err != nil || !ok {
		t.Fatalf("ValidateVersion: %v %v", ok, err)
	}

	// 3. Tests: every required kind, all passing (D34); a simulation.
	if missing, err := a.asr.SetTestCases(aliceCtx, v.ID, assuranceCases(cases)); err != nil || len(missing) != 0 {
		t.Fatalf("SetTestCases: missing %v, %v", missing, err)
	}
	if run, err := a.asr.RunTests(aliceCtx, v.ID); err != nil || !run.Passed {
		t.Fatalf("RunTests: %+v %v", run, err)
	}
	insert, err := jobs.NewClient(s.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	a.asr.Jobs = insert
	sim, err := a.asr.StartSimulation(aliceCtx, v.ID, time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("StartSimulation: %v", err)
	}
	if err := a.asr.RunSimulation(ctx, s.org, sim); err != nil {
		t.Fatalf("RunSimulation: %v", err)
	}
	eventually(t, 60*time.Second, "the simulation", func() (bool, error) {
		got, err := a.asr.GetSimulation(aliceCtx, sim)
		return err == nil && got.State == "DONE", err
	})

	// 4. SHADOW: one confirmation (bob, on the real change page); a signed
	// event starts a SHADOW execution that issues no grant and starts no run.
	en, err := a.core.RequestEnable(aliceCtx, v.ID, autodomain.RolloutShadow, nil, ids.UUID{})
	if err != nil || en.Required != 1 {
		t.Fatalf("RequestEnable SHADOW: %+v %v", en, err)
	}
	if st := bob.confirmAt(t, "/changes/"+en.Request.ID.String()); st != "APPROVED" {
		t.Fatalf("SHADOW enabling after bob: %s", st)
	}
	if code := a.signedEvent(t, source, created.Secret, "msg-1", `{"type":"ticket.created","ref":"T-1"}`); code != http.StatusAccepted {
		t.Fatalf("a signed event: %d", code)
	}
	x := a.latestExecution(t, auto.ID)
	a.advance(t, x)
	if got := s.row(t, "SELECT mode || '/' || state FROM pc.automation_executions WHERE id = $1", x); !strings.HasPrefix(got, "SHADOW/") {
		t.Fatalf("the execution under SHADOW: %s", got)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.runs WHERE automation_execution_id = $1", x); n != "0" {
		t.Fatalf("a SHADOW execution started %s runs", n)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.grants g JOIN pc.automation_ceilings c ON c.org_id = g.org_id AND c.id = g.ceiling_id WHERE c.automation_id = $1", auto.ID); n != "0" {
		t.Fatalf("a SHADOW execution issued %s grants", n)
	}

	// 5. COHORT needs two people (D8): bob, then carol. A signed event now
	// starts a LIVE execution: a grant from the automation's service account
	// under its ceiling, a run, and a launch the real runner claims; the
	// runner refunds through the real gateway, which decides, holds and
	// receipts the refund (HR-285); the confirmed effect finishes the
	// execution SUCCEEDED and its grant is revoked.
	carol := a.confirmer(t, "carol")
	en, err = a.core.RequestEnable(aliceCtx, v.ID, autodomain.RolloutCohort, []ids.UUID{r.agent}, ids.UUID{})
	if err != nil || en.Required != 2 {
		t.Fatalf("RequestEnable COHORT: %+v %v", en, err)
	}
	if st := bob.confirmAt(t, "/changes/"+en.Request.ID.String()); st != "PENDING" {
		t.Fatalf("COHORT enabling after one of two: %s", st)
	}
	if st := carol.confirmAt(t, "/changes/"+en.Request.ID.String()); st != "APPROVED" {
		t.Fatalf("COHORT enabling after both: %s", st)
	}
	live := a.liveRefund(t, auto.ID, source, created.Secret, "msg-2", "T-2")
	a.evidencePack(t, live.execution)

	// 6. Replays and duplicates (HR-275, D21): the same webhook-id is a 409;
	// the same ticket under a new webhook-id is accepted by the receiver and
	// refused REFUSED_DUPLICATE by the automation's dedupe key.
	if code := a.signedEvent(t, source, created.Secret, "msg-2", `{"type":"ticket.created","ref":"T-2"}`); code != http.StatusConflict {
		t.Fatalf("a replayed webhook-id: %d", code)
	}
	if code := a.signedEvent(t, source, created.Secret, "msg-3", `{"type":"ticket.created","ref":"T-2"}`); code != http.StatusAccepted {
		t.Fatalf("the same ticket under a new webhook-id: %d", code)
	}
	if st := s.row(t, "SELECT state FROM pc.automation_triggers WHERE automation_id = $1 ORDER BY received_at DESC, id DESC LIMIT 1", auto.ID); st != "REFUSED_DUPLICATE" {
		t.Fatalf("the duplicate ticket's trigger: %s", st)
	}
	if x := a.latestExecution(t, auto.ID); x != live.execution {
		t.Fatalf("a duplicate started execution %s", x)
	}

	// 7. FULL after the verified COHORT execution, again by two people (D8,
	// D36).
	en, err = a.core.RequestEnable(aliceCtx, v.ID, autodomain.RolloutFull, nil, ids.UUID{})
	if err != nil || en.Required != 2 {
		t.Fatalf("RequestEnable FULL: %+v %v", en, err)
	}
	bob.confirmAt(t, "/changes/"+en.Request.ID.String())
	if st := carol.confirmAt(t, "/changes/"+en.Request.ID.String()); st != "APPROVED" {
		t.Fatalf("FULL enabling after both: %s", st)
	}
	if got := s.row(t, "SELECT state || '/' || rollout FROM pc.automations WHERE id = $1", auto.ID); got != "ACTIVE/FULL" {
		t.Fatalf("the automation after FULL: %s", got)
	}

	a.widen(t, auto.ID, v.ID, source, aliceCtx, bob)
	a.reciprocalLoop(t)
	a.killSwitch(t, auto.ID, source, created.Secret, aliceCtx)
	a.ceilingVoid(t, auto.ID, source, created.Secret)
}

// person is an in-process caller: the user with roles at the org.
func (a *autoStack) person(user ids.UUID, roles ...td.RoleName) context.Context {
	org := a.r.s.org
	bs := make([]td.Binding, 0, len(roles))
	for _, role := range roles {
		bs = append(bs, td.Binding{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Bindings: bs,
	}, Credential: tapp.CredAccessToken})
}

// key is the user's active security key credential.
func (a *autoStack) key(t *testing.T, user ids.UUID) ids.UUID {
	t.Helper()
	return mustUUID(t, a.r.s.row(t, "SELECT id::text FROM pc.webauthn_credentials WHERE user_id = $1 AND state = 'ACTIVE' ORDER BY created_at DESC LIMIT 1", user))
}

// confirmer invites a person who may confirm automation changes (an
// automation publisher who issues grants and launches runs) and signs
// them in with a security key.
func (a *autoStack) confirmer(t *testing.T, name string) keyHolder {
	t.Helper()
	r, s := a.r, a.r.s
	email := name + "@example.test"
	code, invite, errs := r.alice.pclaw(t, "invite", "create", "--email", email, "--role", "automation_publisher")
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite %s: %d %s %s", name, code, invite, errs)
	}
	u := r.people.user(t, name, email)
	u.login(t, s.org.String(), pciToken.FindStringSubmatch(invite)[1])
	id := s.row(t, "SELECT id::text FROM pc.users WHERE subject = $1", name)
	for _, role := range []string{"grant_issuer", "run_launcher"} {
		if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", id); code != 0 {
			t.Fatalf("role bind %s %s: %d %s %s", name, role, code, o, e)
		}
	}
	return signInWithKey(t, s, r.people, name, email)
}

// withRefund adds the runner's refund call to the rendered definition's
// launch step: one HTTP POST of a refund through the payments connection
// (D33, D117).
func (a *autoStack) withRefund(t *testing.T, raw []byte, amount string) []byte {
	t.Helper()
	def, err := autodomain.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i, st := range def.Do {
		if st.Step != "launch_run" {
			continue
		}
		var with map[string]any
		if err := json.Unmarshal(st.With, &with); err != nil {
			t.Fatal(err)
		}
		with["calls"] = []map[string]any{{
			"connection": a.r.s.conn.String(), "face": "HTTP", "method": "POST", "path": "/v1/refunds",
			// Each input value is JSON text (AutomationRunnerCall.input).
			"input": map[string]string{"charge": `"ch_1"`, "amount": `"` + amount + `"`, "currency": `"USD"`, "reason": `"duplicate"`},
		}}
		b, err := json.Marshal(with)
		if err != nil {
			t.Fatal(err)
		}
		def.Do[i].With = jsontext.Value(b)
	}
	// The template names its per-run budget "per-run", which grants refuse
	// as a rule id (lowercase letters, digits and underscores): reported to
	// the coordinator as a cross-stream gap; the test uses a valid id.
	for i := range def.Authority.Ceiling.PerGrant.Limits.Budgets {
		def.Authority.Ceiling.PerGrant.Limits.Budgets[i].ID = strings.ReplaceAll(def.Authority.Ceiling.PerGrant.Limits.Budgets[i].ID, "-", "_")
	}
	out, err := def.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// latestExecution is the automation's newest execution.
func (a *autoStack) latestExecution(t *testing.T, automation ids.UUID) ids.UUID {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		got := a.r.s.row(t, "SELECT coalesce((SELECT id::text FROM pc.automation_executions WHERE automation_id = $1 ORDER BY created_at DESC LIMIT 1), '')", automation)
		if got != "" {
			return mustUUID(t, got)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no execution of %s within 10s; its triggers: %s", automation, a.r.s.row(t, `SELECT coalesce(string_agg(kind || ':' || state || ':' || coalesce(reason, ''),
				', ' ORDER BY received_at), 'none') FROM pc.automation_triggers WHERE automation_id = $1`, automation))
		}
	}
}

// assuranceCases are a template's baseline tests as assurance's cases, as
// the server converts them (wiring_m11_templates.go), except that names
// are slugged: a template's test names have spaces, which assurance's
// name CHECK refuses (reported to the coordinator as a cross-stream gap).
func assuranceCases(cases []templates.TestCase) []assurance.Case {
	out := make([]assurance.Case, 0, len(cases))
	for _, tc := range cases {
		c := assurance.Case{
			Name: slug(tc.Name), Kind: assurance.CaseKind(tc.Kind),
			Expect: assurance.Expect{State: string(tc.Expect.State), Reason: tc.Expect.Reason},
		}
		if len(tc.Trigger.Params) > 0 {
			c.Trigger.Params = make(map[string]string, len(tc.Trigger.Params))
			for k, v := range tc.Trigger.Params {
				c.Trigger.Params[k] = v.Text()
			}
		}
		if len(tc.Expect.Steps) > 0 {
			c.Expect.Steps = make(map[string]string, len(tc.Expect.Steps))
			for k, v := range tc.Expect.Steps {
				c.Expect.Steps[k] = string(v)
			}
		}
		if len(tc.Stubs) > 0 {
			c.Stubs = make(map[string][]assurance.StubResult, len(tc.Stubs))
			for step, rs := range tc.Stubs {
				for _, r := range rs {
					c.Stubs[step] = append(c.Stubs[step], assurance.StubResult{
						State: string(r.State), Effect: string(r.Effect), Reason: r.Reason, Output: r.Output, Evidence: len(r.Refs) > 0,
					})
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// slug is s lower-cased with every run of other characters one hyphen.
func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.TrimSuffix(b.String(), "-")
}

// liveRun is a LIVE execution's grant and run.
type liveRun struct{ execution, grant, run ids.UUID }

// liveRefund sends a signed event for ref, drives its LIVE execution
// through the launch, the real runner and the confirmed refund, and
// checks the grant's provenance and its revocation at the finish.
func (a *autoStack) liveRefund(t *testing.T, automation, source ids.UUID, secret, msgID, ref string) liveRun {
	t.Helper()
	s := a.r.s
	if code := a.signedEvent(t, source, secret, msgID, `{"type":"ticket.created","ref":"`+ref+`"}`); code != http.StatusAccepted {
		t.Fatalf("a signed event: %d", code)
	}
	x := a.latestExecution(t, automation)
	a.advance(t, x)
	var out liveRun
	out.execution = x
	launch := s.row(t, "SELECT coalesce((SELECT grant_id::text || ' ' || run_id::text FROM pc.automation_launches WHERE execution_id = $1), '')", x)
	if launch == "" {
		t.Fatalf("no launch: the execution is %s; attempts: %s", s.row(t, "SELECT mode || '/' || state || '/' || coalesce(reason, '') FROM pc.automation_executions WHERE id = $1", x),
			s.row(t, "SELECT coalesce(string_agg(step_id || ':' || state || ':' || coalesce(reason, '') || ':' || coalesce(output::text, ''), '; '), '') FROM pc.automation_step_attempts WHERE execution_id = $1", x))
	}
	parts := strings.Fields(launch)
	out.grant, out.run = mustUUID(t, parts[0]), mustUUID(t, parts[1])
	// The grant's grantor is the automation's service account, under its
	// ceiling (D9, D69 C1).
	if got := s.row(t, `SELECT g.grantor_kind || ' ' || (g.grantor_id = a.service_account_id)::text || ' ' || (c.automation_id = a.id)::text
		FROM pc.grants g JOIN pc.automation_ceilings c ON c.org_id = g.org_id AND c.id = g.ceiling_id
		JOIN pc.automations a ON a.org_id = c.org_id AND a.id = c.automation_id WHERE g.id = $1`, out.grant); !strings.HasSuffix(got, " true true") {
		t.Fatalf("the launch's grant: %s", got)
	}

	// The real runner claims the launch through the in-process launch
	// service and makes its refund call through the real gateway.
	var stdout, stderr strings.Builder
	if code := pclaw.Run(context.Background(), []string{
		"automation", "runner", "--key", s.keyFile, "--gateway", s.gateway, "--server", a.launches.URL, "--once", "--dev-insecure",
	}, &stdout, &stderr, noEnv, pclaw.Options{}); code != 0 {
		t.Fatalf("pclaw automation runner: %d %s %s", code, stdout.String(), stderr.String())
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.transactions WHERE run_id = $1 AND decision = 'ALLOW'", out.run); n != "1" {
		t.Fatalf("the runner's refund: %s allowed transactions in the run (%s %s)", n, stdout.String(), stderr.String()+" launch: "+s.row(t, "SELECT state || ' ' || coalesce(instance_id::text, '-') || ' ' || delivery FROM pc.automation_launches WHERE run_id = $1", out.run)+" txns: "+s.row(t, "SELECT coalesce(string_agg(decision || '/' || coalesce(effect_state, ''), ','), 'none') FROM pc.transactions WHERE run_id = $1", out.run)+" calls: "+s.row(t, "SELECT calls::text || ' outcome=' || coalesce(outcome, '') || ' report=' || coalesce(report::text, '') FROM pc.automation_launches WHERE run_id = $1", out.run)+" runner: "+stdout.String()+stderr.String())
	}
	// The gateway confirms the refund's effect asynchronously (M7): the
	// execution waits for it.
	eventually(t, 90*time.Second, "the refund's confirmed effect", func() (bool, error) {
		return s.row(t, `SELECT coalesce((SELECT e.state FROM pc.effect_receipts e JOIN pc.transactions x ON x.id = e.transaction_id
			WHERE x.run_id = $1 ORDER BY e.seq DESC LIMIT 1), '')`, out.run) == "CONFIRMED", nil
	})
	eventually(t, 90*time.Second, "the execution to finish", func() (bool, error) {
		a.advance(t, x)
		st := s.row(t, "SELECT state FROM pc.automation_executions WHERE id = $1", x)
		return st != "PENDING" && st != "RUNNING" && st != "WAITING", nil
	})
	if st := s.row(t, "SELECT state || '/' || coalesce(reason, '') FROM pc.automation_executions WHERE id = $1", x); st != "SUCCEEDED/" {
		t.Fatalf("the LIVE execution: %s", st)
	}
	if st := s.row(t, "SELECT state FROM pc.grants WHERE id = $1", out.grant); st != "REVOKED" {
		t.Fatalf("the execution's grant after the finish: %s", st)
	}
	return out
}

// state is an automation's state and pause reason, or an execution's
// state and reason.
func (a *autoStack) automationState(t *testing.T, id ids.UUID) string {
	t.Helper()
	return a.r.s.row(t, "SELECT state || '/' || coalesce(pause_reason, '') FROM pc.automations WHERE id = $1", id)
}

func (a *autoStack) executionState(t *testing.T, id ids.UUID) string {
	t.Helper()
	return a.r.s.row(t, "SELECT state || '/' || coalesce(reason, '') FROM pc.automation_executions WHERE id = $1", id)
}

func (a *autoStack) userID(t *testing.T, subject string) ids.UUID {
	t.Helper()
	return mustUUID(t, a.r.s.row(t, "SELECT id::text FROM pc.users WHERE subject = $1", subject))
}

// killSwitch: a LIVE execution waits for its runner; alice engages the kill
// switch with a step-up; the automation pauses KILL_SWITCH and the
// execution stops (its grant revoked); bob proposes and carol
// confirms the restore, which lifts the switch and resumes nothing; the
// owner then resumes the automation (D14, HR-251).
func (a *autoStack) killSwitch(t *testing.T, automation, source ids.UUID, secret string, owner context.Context) {
	t.Helper()
	s := a.r.s
	if code := a.signedEvent(t, source, secret, "msg-4", `{"type":"ticket.created","ref":"T-4"}`); code != http.StatusAccepted {
		t.Fatalf("a signed event: %d", code)
	}
	x := a.latestExecution(t, automation)
	a.advance(t, x)
	grant := s.row(t, "SELECT coalesce((SELECT grant_id::text FROM pc.automation_launches WHERE execution_id = $1), '')", x)
	if st := a.executionState(t, x); !strings.HasPrefix(st, "WAITING/") || grant == "" {
		t.Fatalf("the execution before the kill switch: %s, grant %q", st, grant)
	}
	alice, bob, carol := a.r.aliceID, a.userID(t, "bob"), a.userID(t, "carol")
	ks := rapp.New(s.pool, nil, s.apiURL).WithPauser(a.core)
	if _, err := ks.Engage(a.person(alice, td.RoleEmergency), rapp.StepUp{Credential: a.key(t, alice), At: time.Now()}, "runaway refunds"); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if st := a.automationState(t, automation); st != "PAUSED/KILL_SWITCH" {
		t.Fatalf("the automation under the kill switch: %s", st)
	}
	a.advance(t, x)
	// It stops with KILL_SWITCH: PARTIALLY_COMPLETED, since it already
	// launched (CANCELLED when it had not acted yet).
	if st := a.executionState(t, x); st != "PARTIALLY_COMPLETED/KILL_SWITCH" && st != "CANCELLED/KILL_SWITCH" {
		t.Fatalf("the waiting execution under the kill switch: %s", st)
	}
	if st := s.row(t, "SELECT state FROM pc.grants WHERE id = $1", grant); st != "REVOKED" {
		t.Fatalf("the cancelled execution's grant: %s", st)
	}
	p, err := ks.ProposeRestore(a.person(bob, td.RoleEmergency), rapp.StepUp{Credential: a.key(t, bob), At: time.Now()}, "contained")
	if err != nil {
		t.Fatalf("ProposeRestore: %v", err)
	}
	if _, err := ks.ConfirmRestore(a.person(carol, td.RoleEmergency), rapp.StepUp{Credential: a.key(t, carol), At: time.Now()}, p.ID); err != nil {
		t.Fatalf("ConfirmRestore: %v", err)
	}
	if st := a.automationState(t, automation); st != "PAUSED/KILL_SWITCH" {
		t.Fatalf("a restore resumed the automation: %s", st)
	}
	if _, _, err := a.core.ResumeAutomation(owner, automation); err != nil {
		t.Fatalf("ResumeAutomation: %v", err)
	}
	if st := a.automationState(t, automation); st != "ACTIVE/" {
		t.Fatalf("the automation after its owner resumed it: %s", st)
	}
}

// ceilingVoid: bob, one of the ceiling's approvers, loses grant.issue; the
// next execution fails CEILING_VOID, the automation pauses CEILING_VOID and
// its owner gets an owned failure (D9, D57, HR-271).
func (a *autoStack) ceilingVoid(t *testing.T, automation, source ids.UUID, secret string) {
	t.Helper()
	s := a.r.s
	binding := s.row(t, "SELECT id::text FROM pc.role_bindings WHERE user_id = $1 AND role = 'grant_issuer'", a.userID(t, "bob"))
	if code, o, e := a.r.alice.pclaw(t, "role", "unbind", binding); code != 0 {
		t.Fatalf("role unbind: %d %s %s", code, o, e)
	}
	if code := a.signedEvent(t, source, secret, "msg-5", `{"type":"ticket.created","ref":"T-5"}`); code != http.StatusAccepted {
		t.Fatalf("a signed event: %d", code)
	}
	x := a.latestExecution(t, automation)
	a.advance(t, x)
	if st := a.executionState(t, x); st != "FAILED/CEILING_VOID" {
		t.Fatalf("the execution after an approver lost grant.issue: %s", st)
	}
	if st := a.automationState(t, automation); st != "PAUSED/CEILING_VOID" {
		t.Fatalf("the automation after its ceiling was voided: %s", st)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.operational_failures WHERE kind = 'automation.authority_changed' AND owner_id = $1", a.r.aliceID); n == "0" {
		t.Fatal("the owner has no owned failure for the void ceiling")
	}
}

// evidencePack: an auditor's evidence pack of the LIVE execution (what it
// was asked, what it did, the grant, the run, the refund's receipts)
// verifies offline with pclaw verify (D30, HR-196).
func (a *autoStack) evidencePack(t *testing.T, execution ids.UUID) {
	t.Helper()
	s := a.r.s
	p := s.proof(t)
	svc := evapp.New(s.pool, p.origin).WithPacks(func(context.Context, db.TenantTx, ids.OrgID, ids.UUID) error { return nil }, a.ents)
	builder := &packbuild.Service{
		Pool: s.pool, Keys: p.reg, LogOrigin: p.origin, Explorer: &txapp.Explorer{Pool: s.pool}, Bundles: evapp.New(s.pool, p.origin),
		Executions: a.engine, Log: pclog.Discard(),
	}
	// The builder reads its creator's permissions from the database: an
	// auditor (evidence.export) who may read automations.
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'pack-auditor')", s.org, id)
	for _, role := range []td.RoleName{td.RoleAuditor, td.RoleAutomationOperator} {
		s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			s.org, ids.NewV7(), string(role), id)
	}
	auditor := a.person(id, td.RoleAuditor, td.RoleAutomationOperator)
	pk, err := svc.CreateEvidencePack(auditor, evapp.PackRequest{Kind: pack.ScopeAutomationExecution, Execution: execution})
	if err != nil {
		t.Fatalf("CreateEvidencePack: %v", err)
	}
	if err := builder.Build(context.Background(), s.org, pk.ID); err != nil {
		t.Fatalf("build the execution pack: %v", err)
	}
	d, err := svc.DownloadEvidencePack(auditor, pk.ID)
	if err != nil {
		t.Fatal(err)
	}
	file := writeFile(t, p.dir, "execution.zip", d.Content)
	if code, rep := p.verify(t, file); code != 0 {
		t.Fatalf("pclaw verify of the execution pack: exit %d\n%+v", code, rep.Checks)
	}
}

// widen: a wider ceiling (USD 100 per grant instead of 50) is a new
// version, validated and tested like any, and enabling it is a new
// two-person ceremony: after one confirmation it is still pending and the
// automation still runs the published version (D5, D8, HR-271).
func (a *autoStack) widen(t *testing.T, automation, published, source ids.UUID, author context.Context, bob keyHolder) {
	t.Helper()
	s := a.r.s
	raw, cases, err := templates.Render("bounded_task_launch", map[string]string{
		"review_by": time.Now().AddDate(0, 0, 60).Format(time.DateOnly), "source": source.String(),
		"event_type": "ticket.created", "agent": a.r.agent.String(), "operations": "payments.refund.create",
		"confirm_operation": "payments.refund.create", "budget_per_run": "100.00", "budget_per_day": "500.00",
		"runs_per_day": "5",
	})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := a.core.CreateDraftVersion(author, automation, a.withRefund(t, raw, "25.00"))
	if err != nil {
		t.Fatalf("CreateDraftVersion (wider): %v", err)
	}
	if _, ok, err := a.core.ValidateVersion(author, v2.ID); err != nil || !ok {
		t.Fatalf("ValidateVersion (wider): %v %v", ok, err)
	}
	if missing, err := a.asr.SetTestCases(author, v2.ID, assuranceCases(cases)); err != nil || len(missing) != 0 {
		t.Fatalf("SetTestCases (wider): %v %v", missing, err)
	}
	if run, err := a.asr.RunTests(author, v2.ID); err != nil || !run.Passed {
		t.Fatalf("RunTests (wider): %+v %v", run, err)
	}
	en, err := a.core.RequestEnable(author, v2.ID, autodomain.RolloutCohort, []ids.UUID{a.r.agent}, ids.UUID{})
	if err != nil || en.Required != 2 {
		t.Fatalf("RequestEnable (wider): %+v %v", en, err)
	}
	if st := bob.confirmAt(t, "/changes/"+en.Request.ID.String()); st != "PENDING" {
		t.Fatalf("the wider ceiling after one confirmation: %s", st)
	}
	if got := s.row(t, "SELECT enabled_version_id::text FROM pc.automations WHERE id = $1", automation); got != published.String() {
		t.Fatalf("a wider ceiling took effect before its ceremony: enabled %s, published %s", got, published)
	}
}

// reciprocalLoop: ping starts on grant.revoked and pong on grant.issued. A
// person's revocation starts ping; ping's work (a grant issued) starts pong
// (its lineage names ping); pong's work (a grant revoked) comes back to
// ping, which is refused REFUSED_LOOP and paused LOOP, with one
// grouped alert and one owned failure for the root (D21, T-123). The two
// automations are fixtures in the stack's org, published and in SHADOW (a
// loop is a trigger refusal, whatever the mode), so the check runs on the
// real trigger service and engine.
func (a *autoStack) reciprocalLoop(t *testing.T) {
	t.Helper()
	s, ctx := a.r.s, context.Background()
	f := &triggerstest.Fixture{Pool: s.pool, Org: s.org, User: a.r.aliceID}
	ping := f.Automation(t, "loop-ping", f.Definition(`"event":{"on":"grant.revoked"}`, ""), autodomain.RolloutShadow)
	pong := f.Automation(t, "loop-pong", f.Definition(`"event":{"on":"grant.issued"}`, ""), autodomain.RolloutShadow)
	feed := func() {
		t.Helper()
		if _, err := ledger.ChainAll(ctx, s.pool, s.org, 1000); err != nil {
			t.Fatal(err)
		}
		if _, err := a.triggers.ProcessFeed(ctx, s.org); err != nil {
			t.Fatal(err)
		}
	}
	triggers := func(x triggerstest.Automation) string {
		return s.row(t, "SELECT count(*)::text FROM pc.automation_triggers WHERE automation_id = $1", x.ID)
	}
	// record writes the event and feeds until target has a new trigger: the
	// e2e server chains the ledger too, so the event may not be chained when
	// the test first processes the feed.
	record := func(name string, actor evdomain.Actor, details map[string]string, target triggerstest.Automation) {
		t.Helper()
		before := triggers(target)
		if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: name, Actor: actor, Outcome: audit.Success,
				Object: &audit.Object{Type: "grant", ID: ids.NewV7().String()}, Details: details,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		eventually(t, 15*time.Second, "the feed to take "+name, func() (bool, error) {
			feed()
			return triggers(target) != before, nil
		})
	}
	sa := func(x triggerstest.Automation) evdomain.Actor {
		return evdomain.Actor{Type: "service_account", ID: x.ServiceAccount.String()}
	}
	feed() // the cursor starts at the head
	record("grant.revoked", evdomain.Actor{Type: "user", ID: a.r.aliceID.String()}, nil, ping)
	first := a.latestExecution(t, ping.ID)
	a.advance(t, first)
	// ping's work (a grant issued) starts pong.
	record("grant.issued", sa(ping), map[string]string{"execution": first.String(), "automation": ping.ID.String()}, pong)
	second := a.latestExecution(t, pong.ID)
	a.advance(t, second)
	// pong's work (a grant revoked) comes back to ping: refused, its lineage
	// holds ping.
	record("grant.revoked", sa(pong), map[string]string{"execution": second.String(), "automation": pong.ID.String()}, ping)
	if n := s.row(t, "SELECT count(*)::text FROM pc.automation_triggers WHERE automation_id = $1 AND state = 'REFUSED_LOOP'", ping.ID); n == "0" {
		t.Fatal("ping was not refused REFUSED_LOOP")
	}
	if got := s.row(t, `SELECT ancestry::text FROM pc.automation_triggers WHERE automation_id = $1 AND state IN ('ACCEPTED', 'SHADOW')
		ORDER BY received_at DESC LIMIT 1`, pong.ID); !strings.Contains(got, ping.ID.String()) {
		t.Fatalf("pong's lineage does not name ping: %s", got)
	}
	if st := a.automationState(t, ping.ID); st != "PAUSED/LOOP" {
		t.Fatalf("ping after the loop: %s", st)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.alerts WHERE rule_id = 'automation.loop'"); n != "1" {
		t.Fatalf("loop alerts: %s, want one grouped issue", n)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.operational_failures WHERE kind = 'automation.loop_stopped'"); n == "0" {
		t.Fatal("the loop has no owned failure")
	}
}
