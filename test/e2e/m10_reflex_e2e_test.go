// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	cdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/cases/store"
	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	exdomain "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ents is a fixed edition for the in-process services (the e2e server is
// Community: its licence roots are embedded, so no test licence exists).
type ents struct{ e billing.Edition }

func (x ents) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: x.e}, nil
}

// reflexStack is the M10 exit scenario's stack: the seeded org, its
// administrator alice signed in to pclaw, and Connect clients carrying her
// access token.
type reflexStack struct {
	s       *stack
	people  *m2Stack
	alice   *user
	aliceID ids.UUID
	agent   ids.UUID
	bearer  string
}

// bearerOf is a pclaw user's access token, as pclaw saved it.
func bearerOf(t *testing.T, u *user) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(u.dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.AccessToken == "" {
		t.Fatalf("credentials: %v", err)
	}
	return c.AccessToken
}

func (r *reflexStack) client(token string) *connect.Client {
	return connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{token},
	}, r.s.apiURL))
}

func startReflex(t *testing.T) *reflexStack {
	t.Helper()
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p})
	r := &reflexStack{s: s, people: &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}}
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	r.alice = r.people.user(t, "alice", "alice@example.test")
	r.alice.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	r.aliceID = mustUUID(t, s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'"))
	// Alice watches and contains (security_admin: incidents, cases,
	// containment, search, operations, exposure).
	for _, role := range []string{"security_admin"} {
		if code, o, e := r.alice.pclaw(t, "role", "bind", "--role", role, "--user", r.aliceID.String()); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	// Bindings are read at sign-in: sign in again for a token that carries them.
	r.alice.login(t, org, "")
	r.bearer = bearerOf(t, r.alice)
	r.agent = mustUUID(t, s.row(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", s.run))
	return r
}

// eventually retries fn until it returns true or the deadline passes.
func eventually(t *testing.T, within time.Duration, what string, fn func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ok, err := fn()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s (last error %v)", what, within, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// TestE2E_M10_DetectInvestigateRespond is the M10 exit scenario (G0 M10
// D40, as amended by D52, D57, D58, D67).
//
// What runs where. The e2e server is Community (its licence roots are
// embedded, so no test licence exists, D58):
//   - over its public API (Connect RPCs, the workload API, the SSE stream):
//     the agent's refused delegation, detection of pc.authority.self_issue,
//     the alert promoted to an incident, the case API refusing below Team,
//     ProposeResponse and a narrow DENY_ALL on the run with its per-path
//     statuses, the live stream with Last-Event-ID resume, and search;
//   - in-process on the same database, with the real application services
//     and only an edition fake (Team/Business), test HTTP clients and root
//     CAs, and step-up credential fixtures: cases, the business detection
//     probing.denial_burst, exposure, SIEM export, Shared Signals and the
//     identity playbook, and restoration.
//
// The seeded agent has no coverage record, so its route is UNKNOWN: the
// containment stays PARTIAL with the bypass route listed (D52), and the
// case refuses CONTAINED. The ENFORCED agent's CONFIRMED containment needs
// the M9 sandbox closure and runs in TestE2E_M10_ContainEnforcedAgent
// (build tag sandbox).
func TestE2E_M10_DetectInvestigateRespond(t *testing.T) {
	r := startReflex(t)
	s, ctx := r.s, context.Background()
	rc := r.client(r.bearer)
	incidents := pantherclawv1connect.NewIncidentServiceClient(rc)
	response := pantherclawv1connect.NewResponseServiceClient(rc)
	casesRPC := pantherclawv1connect.NewCaseServiceClient(rc)
	search := pantherclawv1connect.NewSearchServiceClient(rc)
	team := ents{billing.Team}
	business := ents{billing.Business}

	// The agent acts once: a refund the gateway dispatches.
	if code, rep := s.refund(t, ids.NewV7(), "5.00"); code != http.StatusOK {
		t.Fatalf("refund: %d %+v", code, rep)
	}
	refundTxn := s.row(t, "SELECT id::text FROM pc.transactions ORDER BY created_at DESC LIMIT 1")

	// 1. Detect. The agent asks to delegate more than its own grant holds:
	// refused and audited, and the Community rule pc.authority.self_issue
	// raises an alert on the real server (PN-006.3).
	// TODO(D67): add a service account's IssueGrant attempt over RPC once
	// core audits rpcauth's refusal of a non-human caller on a human-only
	// procedure, and expect the same alert.
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: s.key, Token: func() string { return s.token }},
	}, s.apiURL)))
	child, err := wc.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: s.run, AgentId: r.agent.String()})
	if err != nil {
		t.Fatalf("StartChildRun: %v", err)
	}
	if _, err := wc.DelegateGrant(ctx, &pantherclawv1.DelegateGrantRequest{
		RunId: s.run, ChildRunId: child.GetRun().GetId(), Bounds: []byte(`{"operations": ["github.*", "payments.*"]}`),
		ExpireTime: timestamppb.New(time.Now().Add(1000 * time.Hour)),
	}); err == nil {
		t.Fatal("a delegation wider than the parent grant was accepted")
	}
	var alert *pantherclawv1.Alert
	eventually(t, 90*time.Second, "the self_issue alert", func() (bool, error) {
		res, err := incidents.ListAlerts(ctx, &pantherclawv1.ListAlertsRequest{RuleId: "pc.authority.self_issue"})
		if err != nil || len(res.GetAlerts()) == 0 {
			return false, err
		}
		alert = res.GetAlerts()[0]
		return true, nil
	})
	if alert.GetSeverity() != "HIGH" || alert.GetBasis() != "OBSERVED" || alert.GetRuleDigest() == "" || alert.GetPackVersion() == "" ||
		!slices.ContainsFunc(alert.GetSubjects(), func(x *pantherclawv1.ReflexSubject) bool {
			return x.GetType() == "agent" && x.GetId() == r.agent.String()
		}) {
		t.Fatalf("alert %+v", alert)
	}
	// Community opens no incident for an ALERT; a responder promotes it.
	promoted, err := incidents.PromoteAlert(ctx, &pantherclawv1.PromoteAlertRequest{Id: alert.GetId(), Note: "self-authorization"})
	if err != nil {
		t.Fatalf("PromoteAlert: %v", err)
	}
	incident := promoted.GetIncident()
	got, err := incidents.GetIncident(ctx, &pantherclawv1.GetIncidentRequest{Id: incident.GetId()})
	if err != nil || len(got.GetAlerts()) != 1 || got.GetAlerts()[0].GetId() != alert.GetId() {
		t.Fatalf("GetIncident: %+v %v", got, err)
	}

	// The Business rule probing.denial_burst: five refused decisions in one
	// run, evaluated by the detection engine in-process with Business
	// entitlements, groups by run.
	for range 5 {
		if code, rep := s.refund(t, ids.NewV7(), "100000.00"); code < 400 {
			t.Fatalf("an over-budget refund was allowed: %d %+v", code, rep)
		}
	}
	burst := r.runEngine(t, business)
	if !slices.Contains(burst, "pc.probing.denial_burst") {
		t.Fatalf("the engine raised %v, want pc.probing.denial_burst; decisions %s; cursor %s; alerts %s", burst,
			s.row(t, "SELECT string_agg(decision || '/' || mode || '/' || reason_code, ' ' ORDER BY created_at) FROM pc.transactions"),
			s.row(t, "SELECT coalesce(string_agg(seq::text, ' '), 'none') FROM pc.detection_cursors"),
			s.row(t, "SELECT coalesce(string_agg(rule_id || ' ' || last_seen::text, '; '), 'none') FROM pc.alerts"))
	}
	if n := s.row(t, `SELECT count(*)::text FROM pc.alerts WHERE rule_id = 'pc.probing.denial_burst' AND group_key = $1`, "run:"+s.run); n != "1" {
		t.Fatalf("denial_burst alerts grouped by the run: %s", n)
	}

	// 2. Investigate. Cases need Team: the server refuses; the case service
	// in-process (Team) opens one from the alert, with a FACT and an open
	// QUESTION.
	if _, err := casesRPC.OpenCase(ctx, &pantherclawv1.OpenCaseRequest{Title: "self-issue"}); connect.CodeOf(err) != connect.CodeFailedPrecondition ||
		!strings.Contains(err.Error(), "EDITION_REQUIRED") {
		t.Fatalf("OpenCase on Community: %v", err)
	}
	cases := &capp.Service{Pool: s.pool, Editions: team}
	aliceCtx := r.inProcess(td.RoleSecurityAdmin)
	incidentID := mustUUID(t, incident.GetId())
	alertID := mustUUID(t, alert.GetId())
	k, err := cases.Open(aliceCtx, capp.OpenRequest{
		Title: "Agent tried to widen its own authority", Alert: &alertID, Incident: &incidentID,
		Subjects:  []reflexdomain.Subject{{Type: reflexdomain.SubjectRun, ID: s.run}, {Type: reflexdomain.SubjectAgent, ID: r.agent.String()}},
		Questions: []string{"Was anything read before the delegation?"},
	})
	if err != nil {
		t.Fatalf("open case: %v", err)
	}
	if _, err := cases.Append(aliceCtx, k.ID, cdomain.Draft{
		Kind: cdomain.KindFact, Text: "The agent's run dispatched a refund before it asked to delegate.", Basis: cdomain.BasisObserved,
		Evidence: []cdomain.EvidenceRef{{Kind: cdomain.EvidenceTransaction, ID: mustUUID(t, refundTxn)}},
	}); err != nil {
		t.Fatalf("fact: %v", err)
	}
	view, err := cases.Get(aliceCtx, k.ID, 0, 0)
	if err != nil || view.OpenQuestions != 1 {
		t.Fatalf("case view: %+v %v", view, err)
	}

	// 3. Respond. ProposeResponse offers a narrow DENY_ALL on the run; it
	// commits without a preview. The gateway path confirms (the gateway
	// acknowledged the epoch), the agent's route has no coverage record, so
	// it stays an unresolved bypass and the action PARTIAL (D52).
	proposed, err := response.ProposeResponse(ctx, &pantherclawv1.ProposeResponseRequest{
		Subject: &pantherclawv1.ResponseSubject{Type: "run", Id: s.run},
	})
	if err != nil || !slices.ContainsFunc(proposed.GetOptions(), func(o *pantherclawv1.ResponseOption) bool {
		return o.GetNarrow() && o.GetControl() == "DENY_ALL" && o.GetScope().GetType() == "run"
	}) {
		t.Fatalf("ProposeResponse: %+v %v", proposed, err)
	}
	caseID := k.ID.String()
	contained, err := response.Contain(ctx, &pantherclawv1.ContainRequest{
		Scope: &pantherclawv1.ResponseSubject{Type: "run", Id: s.run}, Control: "DENY_ALL",
		Reason: "self-authorization attempt", CaseId: &caseID, IncidentId: &incident.Id,
	})
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	actionID := contained.GetActionId()
	var action *pantherclawv1.GetResponseActionResponse
	eventually(t, 60*time.Second, "the gateway path to confirm", func() (bool, error) {
		a, err := response.GetResponseAction(ctx, &pantherclawv1.GetResponseActionRequest{ActionId: actionID})
		if err != nil {
			return false, err
		}
		action = a
		return slices.ContainsFunc(a.GetPaths(), func(p *pantherclawv1.ResponsePath) bool {
			return p.GetType() == "GATEWAY" && p.GetStatus() == "CONFIRMED"
		}), nil
	})
	// Every gateway got the epoch (mediated), but new access is not stopped
	// everywhere while the bypass route is open (D52, F561).
	if a := action.GetAction(); a.GetStatus() != "PARTIAL" || !a.GetMediatedConfirmed() || a.GetFutureConfirmed() ||
		!slices.ContainsFunc(action.GetPaths(), func(p *pantherclawv1.ResponsePath) bool {
			return p.GetType() == "ROUTE" && p.GetMaterial() && p.GetStatus() == "UNRESOLVED"
		}) {
		t.Fatalf("response action %+v", action)
	}
	// The run is refused from now on.
	if code, rep := s.refund(t, ids.NewV7(), "1.00"); code < 400 {
		t.Fatalf("a refund in the contained run: %d %+v", code, rep)
	}
	// The case refuses CONTAINED while its containment is PARTIAL (HR-246).
	if _, err := cases.Append(aliceCtx, k.ID, cdomain.Draft{Kind: cdomain.KindState, State: cdomain.StateContained}); !errors.Is(err, store.ErrNotContained) {
		t.Fatalf("CONTAINED with a PARTIAL action: %v", err)
	}

	// 4. Exposure (Team, in-process): the three views of the agent.
	if _, err := (&recompute.Service{Pool: s.pool, Ents: team, Failures: &failures.Sink{}}).Run(ctx, s.org); err != nil {
		t.Fatalf("exposure recompute: %v", err)
	}
	ex := &exapp.Service{Pool: s.pool, Ents: team}
	for _, v := range []exdomain.View{exdomain.Observed, exdomain.Effective, exdomain.Credential} {
		got, err := ex.Exposure(aliceCtx, exdomain.Filter{Agent: &r.agent, View: v})
		if err != nil {
			t.Fatalf("exposure %s: %v", v, err)
		}
		if v != exdomain.Credential && len(got.Rights) == 0 {
			t.Fatalf("exposure %s of the agent is empty", v)
		}
		for _, right := range got.Rights {
			if right.View != v {
				t.Fatalf("exposure %s holds a %s right", v, right.View)
			}
		}
	}

	// 5. The live stream: bearer header only, Last-Event-ID resumes.
	r.stream(t)

	// 6. Search: alice finds the refund; a person scoped to another team
	// sees nothing of the agent, and nothing of it is counted (T-042).
	found, err := search.Search(ctx, &pantherclawv1.SearchRequest{Query: &pantherclawv1.Query{
		Entity: "transactions", Filters: &pantherclawv1.SearchFilters{Id: &refundTxn},
	}})
	if err != nil || found.GetResult().GetCount() != 1 || len(found.GetResult().GetItems()) != 1 {
		t.Fatalf("search as alice: %+v %v", found, err)
	}
	bob := r.scopedPerson(t, "bob", "bob@example.test", "responder")
	hidden, err := pantherclawv1connect.NewSearchServiceClient(r.client(bearerOf(t, bob))).Search(ctx, &pantherclawv1.SearchRequest{
		Query: &pantherclawv1.Query{Entity: "transactions", Filters: &pantherclawv1.SearchFilters{AgentId: ptr(r.agent.String())}},
	})
	if err != nil || hidden.GetResult().GetCount() != 0 || len(hidden.GetResult().GetItems()) != 0 || hidden.GetResult().GetScopeWhole() {
		t.Fatalf("search as a person of another team: %+v %v", hidden, err)
	}

	// 7. SIEM export (Business, in-process): an OCSF batch reaches an HTTPS
	// receiver with a valid Standard Webhooks signature, and a retried batch
	// keeps its webhook id and every event's metadata.uid.
	r.siemExport(t, business)

	// 8. Shared Signals (Business, in-process): a signed SET opens a case;
	// with the identity playbook enabled by two people, a second SET
	// contains the person.
	r.sharedSignals(t, team, business)

	// 9. Restoration: an independent reviewer lifts the run's control.
	r.restore(t, actionID)

	// 10. Closure. The main case stays OPEN (its containment is PARTIAL);
	// a case that needs no containment closes once its rules hold.
	other, err := cases.Open(aliceCtx, capp.OpenRequest{
		Title: "Duplicate alert", Alert: &alertID,
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: r.agent.String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	closing := cdomain.Draft{
		Kind: cdomain.KindState, State: cdomain.StateClosed, Disposition: cdomain.DispositionFalsePositive,
		CaseImpact: cdomain.ImpactNoneFound,
	}
	if _, err := cases.Append(aliceCtx, other.ID, closing); !errors.Is(err, store.ErrNotContained) {
		t.Fatalf("close without containment or a reason: %v", err)
	}
	closing.NoContainmentNeeded, closing.Reason = true, "The same attempt is handled in the first case."
	if _, err := cases.Append(aliceCtx, other.ID, closing); !errors.Is(err, store.ErrClosureRules) {
		t.Fatalf("close without a fact: %v", err)
	}
	if _, err := cases.Append(aliceCtx, other.ID, cdomain.Draft{
		Kind: cdomain.KindFact, Text: "Same refusal as the first case.",
		Basis: cdomain.BasisObserved, Evidence: []cdomain.EvidenceRef{{Kind: cdomain.EvidenceRun, ID: mustUUID(t, s.run)}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := cases.Append(aliceCtx, other.ID, closing); err != nil {
		t.Fatalf("close: %v", err)
	}
	if v, err := cases.Get(aliceCtx, other.ID, 0, 0); err != nil || v.Case.State != cdomain.StateClosed {
		t.Fatalf("closed case: %+v %v", v.Case, err)
	}
	if v, err := cases.Get(aliceCtx, k.ID, 0, 0); err != nil || v.Case.State != cdomain.StateOpen {
		t.Fatalf("the main case: %+v %v", v.Case, err)
	}
}

func ptr[T any](v T) *T { return &v }

// inProcess is alice as an in-process caller with role at the org.
func (r *reflexStack) inProcess(role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: r.s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: r.aliceID},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: r.s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

// runEngine chains the org's ledger and runs the detection engine until it
// has caught up, with these entitlements, and returns the rules alerts are
// open for.
func (r *reflexStack) runEngine(t *testing.T, e ents) []string {
	t.Helper()
	ctx := context.Background()
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	hooks := &reflexapp.Hooks{Ents: e}
	eng := &engine.Engine{
		Pool: r.s.pool, Builtin: p.Rules, PackVersion: p.Version, Env: env, Raiser: hooks.Raiser(),
		Sink: &failures.Sink{}, Ents: e,
	}
	// The server's own engine job evaluates the org too (as Community); the
	// cursor moves for whichever run first, so the in-process engine only
	// sees what is left: rewind it to the start of this test's events.
	r.s.exec(t, "UPDATE pc.detection_cursors SET seq = 0")
	for range 50 {
		if _, err := ledger.ChainAll(ctx, r.s.pool, r.s.org, 1000); err != nil {
			t.Fatal(err)
		}
		res, err := eng.Process(ctx, r.s.org)
		if errors.Is(err, engine.ErrCursorMoved) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if res.Events == 0 && res.To == res.From {
			break
		}
	}
	var rules []string
	rows := strings.Fields(r.s.row(t, "SELECT coalesce(string_agg(DISTINCT rule_id, ' '), '') FROM pc.alerts"))
	rules = append(rules, rows...)
	return rules
}
