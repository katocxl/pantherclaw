// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	"github.com/katocxl/pantherclaw/internal/changes"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/search"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M11_GovernanceAndSearch is D49's governance and search exit
// scenario (G0 M11 part 2 D39, D42, D43, D44–D48, D96): a production grant
// refused NOT_PROMOTED until a promotion with a step-up; a protected CUSTODY
// change pending until a distinct person confirms it; a publisher marked
// compromised (her pending request voided, her automation paused, the
// change ceremony refusing her); then Find by name, Ask "denied refunds
// last 7 days", a case from the results and an audited export.
//
// What runs where (D96): the real server, Community, for the promotion
// gate, protected changes, the change pages and search; in-process on the
// same database with the real services and only an edition fake, marking
// the compromised publisher (Business) and opening the case (Team).
func TestE2E_M11_GovernanceAndSearch(t *testing.T) {
	r := startReflex(t)
	r.m11Promotion(t)
	bob, _, bobID := r.m11Custody(t)
	r.m11Compromise(t, bob, bobID)
	r.m11Search(t)
}

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
	for _, role := range []string{"agent_owner", "agent_admitter", "grant_issuer", "fleet_manager", "approver"} {
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

	// The checks run for real (alice is also an approver, so the seeded
	// policy's large-refund approvals have someone eligible): the scenario
	// tests and the route's coverage are recorded as a team would; the promotion itself is alice's, on the
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
		t.Fatalf("promote: %d %v; failing checks: %s", code, out, r.failingChecks(t, agent, env, "payments.refund.create"))
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

// changeRequestID is the change request a held protected change names.
var changeRequestID = regexp.MustCompile(`change request ([0-9a-f-]{36})`)

// m11Custody is the protected-change part of the M11 exit scenario (G0 M11
// part 2 D42, D49, HR-292), on the real server: alice turns CUSTODY on; her
// weakening of a route to monitor is held PENDING, not applied; she cannot
// confirm her own change; bob, a distinct security and gateway
// administrator, confirms it with his security key and only then does the
// route change.
// It returns bob, his key and his id.
func (r *reflexStack) m11Custody(t *testing.T) (*user, keyHolder, string) {
	t.Helper()
	s, ctx := r.s, context.Background()
	for _, role := range []string{"security_admin", "gateway_admin"} {
		if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", r.aliceID.String()); code != 0 &&
			!strings.Contains(e, "ROLE_BINDING_EXISTS") {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	r.alice.login(t, s.org.String(), "")
	rc := r.client(bearerOf(t, r.alice))
	protected := pantherclawv1connect.NewProtectedChangeServiceClient(rc)
	conns := pantherclawv1connect.NewConnectionServiceClient(rc)
	if _, err := protected.SetProtectedCategoryMode(ctx, &pantherclawv1.SetProtectedCategoryModeRequest{
		Category: "CUSTODY", Mode: "DISTINCT_PUBLISHER",
	}); err != nil {
		t.Fatalf("turn CUSTODY on: %v", err)
	}

	const route = "payments-refund"
	mode := func() pantherclawv1.RouteMode {
		t.Helper()
		got, err := conns.GetConnection(ctx, &pantherclawv1.GetConnectionRequest{Id: s.conn.String()})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range got.GetConnection().GetRoutes() {
			if x.GetRoute() == route {
				return x.GetMode()
			}
		}
		return got.GetConnection().GetDefaultMode()
	}
	if m := mode(); m != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE {
		t.Fatalf("the route starts in %v", m)
	}
	_, err := conns.SetRouteMode(ctx, &pantherclawv1.SetRouteModeRequest{
		ConnectionId: s.conn.String(), Route: route, Mode: pantherclawv1.RouteMode_ROUTE_MODE_MONITOR,
	})
	held := changeRequestID.FindStringSubmatch(errMessage(err))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(errMessage(err), "PROTECTED_CHANGE_PENDING") || held == nil {
		t.Fatalf("a custody weakening with CUSTODY on: %v", err)
	}
	if m := mode(); m != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE {
		t.Fatalf("a held change applied: the route is %v", m)
	}

	// Alice cannot confirm her own change.
	alice := signInWithKey(t, s, r.people, "alice", "alice@example.test")
	if code, body := alice.b.post(t, "/changes/"+held[1]+"/confirm-options", map[string]any{}); code != http.StatusForbidden ||
		string(body["error"]) != `"not_eligible"` {
		t.Fatalf("the author confirming her own change: %d %v", code, body)
	}
	// Bob, a second security and gateway administrator (the change pages
	// need protected_change.manage, confirming the surface's own
	// connection.manage), confirms it.
	code, invite, errs := r.alice.pclaw(t, "invite", "create", "--email", "bob@example.test", "--role", "security_admin")
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite bob: %d %s %s", code, invite, errs)
	}
	bob := r.people.user(t, "bob", "bob@example.test")
	bob.login(t, s.org.String(), pciToken.FindStringSubmatch(invite)[1])
	bobID := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'bob'")
	if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", "gateway_admin", "--user", bobID); code != 0 {
		t.Fatalf("role bind gateway_admin: %d %s %s", code, o, e)
	}
	bk := signInWithKey(t, s, r.people, "bob", "bob@example.test")
	if state := bk.confirmAt(t, "/changes/"+held[1]); state != "APPROVED" {
		t.Fatalf("the change request after bob's confirmation: %s", state)
	}
	if m := mode(); m != pantherclawv1.RouteMode_ROUTE_MODE_MONITOR {
		t.Fatalf("the confirmed change did not apply: the route is %v", m)
	}
	// Back to enforce: a narrowing applies at once, nothing is held.
	if _, err := conns.SetRouteMode(ctx, &pantherclawv1.SetRouteModeRequest{
		ConnectionId: s.conn.String(), Route: route, Mode: pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE,
	}); err != nil {
		t.Fatalf("back to enforce: %v", err)
	}
	if m := mode(); m != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE {
		t.Fatalf("the route after narrowing: %v", m)
	}
	return bob, bk, bobID
}

func errMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// confirmAt confirms the change request whose page is path with the
// person's key, as the page's script does, and returns its state.
func (k keyHolder) confirmAt(t *testing.T, path string) string {
	t.Helper()
	if code, page := k.b.page(t, path); code != http.StatusOK {
		t.Fatalf("change request page: %d %s", code, page)
	}
	code, body := k.b.post(t, path+"/confirm-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("confirm options: %d %v", code, body)
	}
	resp, err := k.key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	code, out := k.b.post(t, path+"/confirm", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)})
	if code != http.StatusOK {
		t.Fatalf("confirm: %d %v", code, out)
	}
	var state string
	if err := json.Unmarshal(out["state"], &state); err != nil {
		t.Fatal(err)
	}
	return state
}

// m11Compromise is the compromised-publisher part of the M11 exit scenario
// (G0 M11 part 2 D43, D49, D69 C13, HR-293). Marking needs Business, so it
// runs in-process on the same database with the real services, wired as
// the server wires them (wiring_m11_protect.go protectCore): bob marks
// alice compromised with a fresh step-up of his security key; in that
// transaction her pending protected change is voided and the automation
// whose ceiling she approved is paused. Back on the real server, the
// change ceremony's CompromiseChecker refuses her as a confirmer (K9).
func (r *reflexStack) m11Compromise(t *testing.T, bob *user, bobID string) {
	t.Helper()
	s, ctx := r.s, context.Background()
	const route = "payments-refund"
	monitor := func(who *connect.Client) string {
		t.Helper()
		_, err := pantherclawv1connect.NewConnectionServiceClient(who).SetRouteMode(ctx, &pantherclawv1.SetRouteModeRequest{
			ConnectionId: s.conn.String(), Route: route, Mode: pantherclawv1.RouteMode_ROUTE_MODE_MONITOR,
		})
		held := changeRequestID.FindStringSubmatch(errMessage(err))
		if held == nil {
			t.Fatalf("a held custody change: %v", err)
		}
		return held[1]
	}
	alicePending := monitor(r.client(bearerOf(t, r.alice)))

	// An automation alice approved the ceiling of, ACTIVE.
	auto := (&exposuretest.Org{P: s.pool, Org: s.org, User: r.aliceID, Agent: r.agent}).
		Automation(t, "refund-follow-up", []ids.UUID{r.agent}, "payments.refund.create")

	business := ents{billing.Business}
	ch := changes.New(s.pool, s.apiURL)
	core := &autoapp.Service{Pool: s.pool, Clock: clock.System{}, Changes: ch, Editions: business, Failures: &failures.Sink{}}
	gate := &protect.Gate{Requests: protect.Ceremony{Changes: ch}}
	pub := &protect.Publishers{Pool: s.pool, Gate: gate, Editions: business, Undo: map[string]protect.Rollback{}}
	gate.Compromise, ch.Compromise, core.Compromise = pub, pub, pub
	pub.On = append(pub.On,
		func(ctx context.Context, tx db.TenantTx, user ids.UUID, _ time.Time, by tapp.Caller) (map[string]string, error) {
			voided, err := ch.VoidByPerson(ctx, tx, by, user, "PUBLISHER_COMPROMISED")
			return map[string]string{"change_requests_voided": strconv.Itoa(len(voided))}, err
		},
		func(ctx context.Context, tx db.TenantTx, user ids.UUID, _ time.Time, _ tapp.Caller) (map[string]string, error) {
			ceilings, err := dbq.New(tx).CeilingsApprovedBy(ctx, tx.OrgID(), user)
			if err != nil {
				return nil, err
			}
			var autos []ids.UUID
			for _, c := range ceilings {
				autos = append(autos, c.AutomationID)
			}
			paused, err := core.Pause(ctx, tx.Pgx(), tx.OrgID(), autodomain.PauseSelector{Automations: autos},
				autodomain.PauseCompromisedPublisher)
			return map[string]string{"automations_paused": strconv.Itoa(len(paused))}, err
		})

	bobCtx := tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: mustUUID(t, bobID)},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	key := mustUUID(t, s.row(t, "SELECT id::text FROM pc.webauthn_credentials WHERE user_id = $1 AND state = 'ACTIVE'", bobID))
	if _, err := pub.MarkCompromised(bobCtx, r.aliceID, time.Now().Add(-time.Hour), "phished", stepup.StepUp{}); err == nil {
		t.Fatal("marking without a step-up was accepted")
	}
	if _, err := pub.MarkCompromised(bobCtx, r.aliceID, time.Now().Add(-time.Hour), "phished",
		stepup.StepUp{Credential: key, At: time.Now()}); err != nil {
		t.Fatalf("MarkCompromised: %v", err)
	}
	if st := s.row(t, "SELECT state FROM pc.change_requests WHERE id = $1", alicePending); st != "VOIDED" {
		t.Fatalf("alice's pending protected change: %s", st)
	}
	if st := s.row(t, "SELECT state || '/' || coalesce(pause_reason, '') FROM pc.automations WHERE id = $1", auto.ID); st !=
		"PAUSED/COMPROMISED_PUBLISHER" {
		t.Fatalf("the automation alice approved: %s", st)
	}

	// The real server's change ceremony refuses her as a confirmer (D69
	// C13, K9): bob's own weakening waits for someone else.
	bobPending := monitor(r.client(bearerOf(t, bob)))
	alice := signInWithKey(t, s, r.people, "alice", "alice@example.test")
	if code, body := alice.b.post(t, "/changes/"+bobPending+"/confirm-options", map[string]any{}); code != http.StatusForbidden ||
		string(body["error"]) != `"compromised"` {
		t.Fatalf("a compromised person confirming a change: %d %v", code, body)
	}
}

// failingChecks lists the promotion checks an operation fails, for a
// refusal's message.
func (r *reflexStack) failingChecks(t *testing.T, agent, env, op string) string {
	t.Helper()
	res, err := pantherclawv1connect.NewPromotionServiceClient(r.client(bearerOf(t, r.alice))).GetReadiness(context.Background(),
		&pantherclawv1.GetReadinessRequest{AgentId: agent, EnvironmentId: env, Operations: []string{op}})
	if err != nil {
		return err.Error()
	}
	var out []string
	for _, x := range res.GetReadiness() {
		for _, c := range x.GetChecks() {
			if !c.GetPassed() {
				out = append(out, c.GetName()+": "+c.GetDetail())
			}
		}
	}
	return strings.Join(out, "; ")
}
