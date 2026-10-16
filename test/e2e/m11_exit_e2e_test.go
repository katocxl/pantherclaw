// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
	"github.com/katocxl/pantherclaw/internal/search"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m11Search is the search part of the M11 exit scenario (G0 M11 part 2
// D49): over the real server, alice finds the agent by name, asks "denied
// refunds last 7 days" and gets the deterministic interpretation and the
// denied refund only, and exports the results with an audit record; in
// process with Team, she opens a case from the results.
func (r *reflexStack) m11Search(t *testing.T) {
	t.Helper()
	s, ctx := r.s, context.Background()
	rpc := pantherclawv1connect.NewSearchServiceClient(r.client(r.bearer))

	// One allowed refund and one over the grant's per-refund limit.
	if code, rep := s.refund(t, ids.NewV7(), "5.00"); code != http.StatusOK {
		t.Fatalf("refund: %d %+v", code, rep)
	}
	allowed := s.row(t, "SELECT id::text FROM pc.transactions ORDER BY created_at DESC LIMIT 1")
	if code, rep := s.refund(t, ids.NewV7(), "125.00"); code != http.StatusForbidden || rep.Decision != "DENY" {
		t.Fatalf("over-limit refund: %d %+v", code, rep)
	}
	denied := s.row(t, "SELECT id::text FROM pc.transactions ORDER BY created_at DESC LIMIT 1")

	// Find by name: the agent, by a prefix of its name.
	name := s.row(t, "SELECT name FROM pc.agents WHERE id = $1", r.agent)
	found, err := rpc.Find(ctx, &pantherclawv1.FindRequest{Text: name[:min(len(name), 4)], Kinds: []string{"agents"}})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(found.GetKinds()) != 1 || !slices.ContainsFunc(found.GetKinds()[0].GetMatches(), func(m *pantherclawv1.FindMatch) bool {
		return m.GetId() == r.agent.String()
	}) {
		t.Fatalf("Find %q: %+v", name, found)
	}

	// Ask: the interpretation is shown, nothing is guessed, and the answer
	// holds the denied refund and not the allowed one.
	asked, err := rpc.Ask(ctx, &pantherclawv1.AskRequest{Question: "denied refunds last 7 days", Timezone: "UTC"})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	in := asked.GetInterpretation()
	if in.GetNeedsClarification() || len(in.GetUnknownWords()) != 0 || in.GetEntity() != "transactions" || in.GetQuery() == nil ||
		in.GetRangeStartTime() == nil || asked.GetResult() == nil {
		t.Fatalf("interpretation: %+v", in)
	}
	var got []string
	for _, it := range asked.GetResult().GetItems() {
		got = append(got, it.GetId())
	}
	if !slices.Contains(got, denied) || slices.Contains(got, allowed) {
		t.Fatalf("denied refunds: %v (denied %s, allowed %s)", got, denied, allowed)
	}
	source := &pantherclawv1.SearchSource{Query: in.GetQuery()}

	// Export: CSV, audited in the ledger with the query's digest.
	exp, err := rpc.ExportResults(ctx, &pantherclawv1.ExportResultsRequest{Source: source, Format: "CSV"})
	if err != nil {
		t.Fatalf("ExportResults: %v", err)
	}
	if exp.GetRows() < 1 || !strings.Contains(string(exp.GetData()), denied) || exp.GetAuditEntryId() == "" {
		t.Fatalf("export: %d rows, audit %q", exp.GetRows(), exp.GetAuditEntryId())
	}
	if body := s.row(t, `SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE kind = 'audit.search.exported'
		ORDER BY occurred_at DESC, id DESC LIMIT 1`); !strings.Contains(body, "transactions") || !strings.Contains(body, "query_sha256") {
		t.Fatalf("export audit: %s", body)
	}

	// A case from the results: Team, so in-process; the search runs again
	// under alice and only the chosen row seeds the case.
	team := ents{billing.Team}
	svc := &search.Service{
		Pool: s.pool, Defs: &defspg.Store{Pool: s.pool}, Clock: clock.System{}, Cases: capp.NewOpener(team), Editions: team,
	}
	alice := r.inProcess(td.RoleSecurityAdmin)
	local, err := svc.Interpret(alice, "denied refunds last 7 days", "UTC")
	if err != nil || local.Query == nil {
		t.Fatalf("Interpret: %+v %v", local, err)
	}
	caseID, err := svc.OpenCaseFromResults(alice, search.OpenCaseRequest{
		Source: search.Source{Query: local.Query}, Items: []string{denied}, Title: "Denied refunds",
	})
	if err != nil {
		t.Fatalf("OpenCaseFromResults: %v", err)
	}
	if ev := s.row(t, `SELECT count(*)::text FROM pc.case_entries
		WHERE case_id = $1 AND kind = 'LINK' AND ref_kind = 'transaction' AND lower(ref_id) = $2`, caseID, denied); ev != "1" {
		t.Fatalf("case %s holds the denied refund %s times", caseID, ev)
	}
}

// m11Promotion is the promotion gate part of the M11 exit scenario (G0 M11
// part 2 D39, D49, HR-290), on the real server: a grant for an agent in a
// PRODUCTION environment is refused NOT_PROMOTED; alice, a fleet manager,
// promotes the agent for refunds on the promotion page with a fresh
// step-up of her security key; the same grant is then issued.
func (r *reflexStack) m11Promotion(t *testing.T) {
	t.Helper()
	s := r.s
	must := func(args ...string) string {
		t.Helper()
		code, o, e := r.alice.pclaw(t, args...)
		if code != 0 {
			t.Fatalf("pclaw %s: %d %s %s", strings.Join(args, " "), code, o, e)
		}
		return o
	}
	for _, role := range []string{"agent_owner", "agent_admitter", "grant_issuer", "fleet_manager"} {
		if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", r.aliceID.String()); code != 0 &&
			!strings.Contains(e, "ROLE_BINDING_EXISTS") {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	r.alice.login(t, s.org.String(), "")
	team := field(t, must("team", "create", "--slug", "payments", "--name", "Payments"), "id")
	env := field(t, must("env", "create", "--team", team, "--slug", "prod", "--name", "Production", "--kind", "prod"), "id")
	agent := field(t, must("agent", "create", "--name", "prod-refunder", "--team", team, "--env", env, "--owner", r.aliceID.String(),
		"--context", "service"), "id")
	work := t.TempDir()
	enrollFile, keyFile := filepath.Join(work, "enroll.token"), filepath.Join(work, "workload.json")
	must("agent", "enroll-token", agent, "--out", enrollFile)
	must("workload", "init", "--key-file", keyFile)
	o := must("workload", "enroll", "--key-file", keyFile, "--server", s.apiURL, "--enrollment-token-file", enrollFile)
	inst, fp := enrolledInstance.FindStringSubmatch(o), enrolledPrint.FindStringSubmatch(o)
	if inst == nil || fp == nil {
		t.Fatalf("enroll output %q", o)
	}
	must("instance", "admit", inst[1], "--fingerprint", fp[1])

	bounds := filepath.Join(work, "bounds.json")
	if err := os.WriteFile(bounds, []byte(`{"operations": ["payments.refund.create"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	issue := func() (int, string, string) {
		return r.alice.pclaw(t, "grant", "issue", agent, "--principal", "user:"+r.aliceID.String(), "--expires", "24h", "--bounds-file", bounds)
	}
	if code, _, e := issue(); code == 0 || !strings.Contains(e, "NOT_PROMOTED") {
		t.Fatalf("a production grant before the promotion: %d %s", code, e)
	}

	// The checks run for real: the scenario tests and the route's coverage
	// are recorded as a team would; the promotion itself is alice's, on the
	// page, with a step-up.
	promotiontest.Record(t, promotiontest.Scope{
		Pool: s.pool, Org: s.org, Agent: mustUUID(t, agent), Env: mustUUID(t, env), Connection: s.conn, Publish: policytest.Publish,
	}, "payments.refund.create")
	k := signInWithKey(t, s, r.people, "alice", "alice@example.test")
	path := "/agents/" + agent + "/promote"
	if code, page := k.b.page(t, path+"?environment="+env+"&operation=payments.refund.create"); code != http.StatusOK {
		t.Fatalf("promotion page: %d %s", code, page)
	}
	body := map[string]any{"environment_id": env, "operations": []string{"payments.refund.create"}, "failure_behavior": "FAIL_CLOSED"}
	if code, out := k.b.post(t, path, body); code != http.StatusForbidden {
		t.Fatalf("a promotion without a step-up: %d %v", code, out)
	}
	k.stepUp(t)
	code, out := k.b.post(t, path, body)
	if code != http.StatusOK || !strings.Contains(string(out["promoted"]), "payments.refund.create") {
		t.Fatalf("promote: %d %v", code, out)
	}
	if code, o, e := issue(); code != 0 || field(t, o, "id") == "" {
		t.Fatalf("the production grant after the promotion: %d %s %s", code, o, e)
	}
}

// stepUp verifies the person's key again for a fresh step-up.
func (k keyHolder) stepUp(t *testing.T) {
	t.Helper()
	code, body := k.b.post(t, "/account/step-up-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("step-up options: %d %v", code, body)
	}
	resp, err := k.key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, body = k.b.post(t, "/account/step-up", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)}); code != http.StatusOK {
		t.Fatalf("step-up: %d %v", code, body)
	}
}
