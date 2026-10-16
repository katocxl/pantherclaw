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
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
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
			"input": map[string]string{"charge": "ch_1", "amount": amount, "currency": "USD", "reason": "duplicate"},
		}}
		b, err := json.Marshal(with)
		if err != nil {
			t.Fatal(err)
		}
		def.Do[i].With = jsontext.Value(b)
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
	var id ids.UUID
	eventually(t, 10*time.Second, "an execution", func() (bool, error) {
		got := a.r.s.row(t, "SELECT coalesce((SELECT id::text FROM pc.automation_executions WHERE automation_id = $1 ORDER BY created_at DESC LIMIT 1), '')", automation)
		if got == "" {
			return false, nil
		}
		id = mustUUID(t, got)
		return true, nil
	})
	return id
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
