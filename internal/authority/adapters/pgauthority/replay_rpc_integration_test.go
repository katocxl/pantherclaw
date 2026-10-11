// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/evidence/adapters/evidencerpc"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// callers authenticates bearer names as fixed callers (the tests' stand-in
// for access tokens; the permission interceptor and protovalidate run as in
// the server).
type callers map[string]tapp.Caller

func (c callers) Authenticate(_ context.Context, bearer string) (tapp.Caller, error) {
	if cl, ok := c[bearer]; ok {
		return cl, nil
	}
	return tapp.Caller{}, pcerr.New(pcerr.Unauthenticated, "UNAUTHENTICATED", "invalid or expired credentials")
}

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

// replayAPI serves EvidenceService for w's org over HTTP, with the replay
// engine of the server and a fake clock for the rate limit.
type replayAPI struct {
	url     string
	clk     *clock.Fake
	callers callers
}

func (w *world) replayAPI() *replayAPI {
	w.t.Helper()
	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "..", "proto"))
	if err != nil {
		w.t.Fatal(err)
	}
	perms := map[string]td.Permission{}
	for proc, p := range declared {
		perms[proc] = td.Permission(p)
	}
	api := &replayAPI{clk: clock.NewFake(time.Now()), callers: callers{}}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(api.callers, perms, nil)})
	if err != nil {
		w.t.Fatal(err)
	}
	svc := evapp.New(w.pool, "pc.test").WithReplay(w.replayEngine(), api.clk)
	pantherclawv1connect.RegisterEvidenceServiceHandler(s, evidencerpc.New(svc))
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	w.t.Cleanup(ts.Close)
	api.url = ts.URL
	return api
}

// as registers a caller of org with bindings and returns its client.
func (a *replayAPI) as(name string, org ids.OrgID, kind td.PrincipalKind, bs ...td.Binding) pantherclawv1connect.EvidenceServiceClient {
	a.callers[name] = tapp.Caller{Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: kind, ID: ids.NewV7()}, Bindings: bs}}
	return pantherclawv1connect.NewEvidenceServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: bearerRT{name},
	}, a.url)))
}

func replayCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	var ce *connect.Error
	if !errors.As(err, &ce) || ce.Code() != want {
		t.Fatalf("%s: %v, want %s", what, err, want)
	}
}

func (w *world) teamOfAgent() ids.UUID {
	w.t.Helper()
	var team ids.UUID
	w.db.AdminQueryRow(w.t, "SELECT team_id FROM pc.agents WHERE id = $1", []any{w.agent}, &team)
	return team
}

// TestHR197_ReplayDecisionThroughTheRPC: ReplayDecision, served as the API
// serves it, replays an allowed, a held and a denied decision unchanged and
// under a proposed policy version without writing a row anywhere (no
// transaction, receipt, reservation, permit, claim, ledger entry or audit
// event) and without any gateway (the engine has none: no permit is issued
// or dispatched, F508). The unchanged replays reproduce; the proposed
// policy denies the allowed refund and names the rule that differs (F505,
// F506); the latest evaluation is the default.
func TestHR197_ReplayDecisionThroughTheRPC(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1", "ch_2")
	w.publishPolicy(1, false, pgHoldOver50)
	draft := w.publishPolicy(2, true, pgHoldOver50, pgForbidOver20)
	run := w.run(w.grant("500").ID, ids.UUID{})
	results := []finalize.Result{
		w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00")),
		w.authorize(w.request(run, ids.NewV7(), "ch_2", "70.00")),
		w.authorize(w.request(run, ids.NewV7(), "ch_2", "125.00")),
	}
	if results[0].Decision != adomain.Allow || results[1].Decision != adomain.RequireApproval || results[2].Decision != adomain.Deny {
		t.Fatalf("decisions: %s %s %s", results[0].Decision, results[1].Decision, results[2].Decision)
	}
	api := w.replayAPI()
	auditor := api.as("auditor", w.org, td.KindUser, td.Binding{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	ctx := context.Background()

	before := w.rowCounts()
	for _, r := range results {
		res, err := auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{TransactionId: r.TransactionID.String()})
		if err != nil {
			t.Fatal(err)
		}
		want := pantherclawv1.Decision(pantherclawv1.Decision_value["DECISION_"+string(r.Decision)])
		if !res.GetReproduced() || !res.GetComplete() || res.GetDecision() != want || res.GetOriginalDecision() != want ||
			res.GetBasisDigest() != r.BasisDigest || res.GetPolicy() != "org-policy@1" || res.GetEvaluation() != int32(r.Evaluation) || //nolint:gosec // G115
			len(res.GetChecklist()) == 0 || len(res.GetInputs()) != 0 {
			t.Errorf("unchanged replay of %s: %v", r.Decision, res)
		}
		if _, err := auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{
			TransactionId: r.TransactionID.String(), Evaluation: 1, PolicyVersionId: draft.String(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	proposed, err := auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{
		TransactionId: results[0].TransactionID.String(), PolicyVersionId: draft.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !proposed.GetComplete() || !proposed.GetProposed() || proposed.GetReproduced() || proposed.GetSameDecision() ||
		proposed.GetDecision() != pantherclawv1.Decision_DECISION_DENY || proposed.GetReason() != "REFUND_TOO_LARGE" ||
		proposed.GetOriginalDecision() != pantherclawv1.Decision_DECISION_ALLOW ||
		!slices.ContainsFunc(proposed.GetDifferences(), func(d *pantherclawv1.ReplayDifference) bool {
			return d.GetStep() == int32(pipeline.StepBoundaries) && slices.Equal(d.GetRules(), []string{"no-large-refunds"})
		}) {
		t.Fatalf("proposed: %v", proposed)
	}
	after := w.rowCounts()
	for tb, n := range before {
		if after[tb] != n {
			t.Errorf("table %s: %d rows before the replays, %d after", tb, n, after[tb])
		}
	}
	if len(after) != len(before) || len(before) < 50 || before["decision_receipts"] != 3 || before["evaluation_inputs"] != 3 {
		t.Fatalf("tables counted: %d before, %d after; receipts %d, inputs %d", len(before), len(after),
			before["decision_receipts"], before["evaluation_inputs"])
	}

	// Not found: an evaluation the transaction does not have, a policy
	// version of no one, a transaction of no one.
	_, err = auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{TransactionId: results[0].TransactionID.String(), Evaluation: 2})
	replayCode(t, "a missing evaluation", err, connect.CodeNotFound)
	_, err = auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{
		TransactionId: results[0].TransactionID.String(), PolicyVersionId: ids.NewV7().String(),
	})
	replayCode(t, "an unknown policy version", err, connect.CodeNotFound)
	_, err = auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{TransactionId: ids.NewV7().String()})
	replayCode(t, "an unknown transaction", err, connect.CodeNotFound)
	_, err = auditor.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{TransactionId: "not-a-uuid"})
	replayCode(t, "an invalid id", err, connect.CodeInvalidArgument)
}

// TestHR197_ReplayInputValuesNeedReadRestricted: outcomes and checklists
// need evidence.read; the recorded input values come back only to a holder
// of evidence.read_restricted (design decision 11). A Developer (and an
// Org Admin) get the replay without them and the reason; an Auditor gets
// them; a service account never holds the human-only permission.
func TestHR197_ReplayInputValuesNeedReadRestricted(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1")
	r := w.authorize(w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	api := w.replayAPI()
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	ctx := context.Background()
	req := &pantherclawv1.ReplayDecisionRequest{TransactionId: r.TransactionID.String(), IncludeInputs: true}

	for name, role := range map[string]td.RoleName{"developer": td.RoleDeveloper, "org-admin": td.RoleOrgAdmin} {
		res, err := api.as(name, w.org, td.KindUser, td.Binding{Role: role, Scope: org}).ReplayDecision(ctx, req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.GetReproduced() || len(res.GetInputs()) != 0 || res.GetInputsWithheld() != evapp.WithheldPermission {
			t.Fatalf("%s: inputs %d bytes, withheld %q", name, len(res.GetInputs()), res.GetInputsWithheld())
		}
	}
	res, err := api.as("auditor", w.org, td.KindUser, td.Binding{Role: td.RoleAuditor, Scope: org}).ReplayDecision(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if res.GetInputsWithheld() != "" || len(res.GetInputs()) == 0 {
		t.Fatalf("auditor: withheld %q", res.GetInputsWithheld())
	}
	var rec recording.Recording
	if err := json.Unmarshal(res.GetInputs(), &rec); err != nil || rec.Request.Agent != w.agent.String() || len(rec.Reads.Facts) == 0 {
		t.Fatalf("the returned inputs are not the recording: %v", err)
	}
	// A service account bound to Auditor holds its evidence.read but never
	// the human-only evidence.read_restricted: it gets the replay without
	// the values.
	sa := api.as("service-account", w.org, td.KindServiceAccount, td.Binding{Role: td.RoleAuditor, Scope: org})
	res, err = sa.ReplayDecision(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetInputs()) != 0 || res.GetInputsWithheld() != evapp.WithheldPermission {
		t.Fatalf("service account: inputs %d bytes", len(res.GetInputs()))
	}
}

// TestHR197_ReplayIsScopedLikeRunRead: evidence.read must hold where the
// transaction's agent lives (T-042); a Viewer has no evidence.read at all;
// another org's transaction is not found (T-037, IDOR).
func TestHR197_ReplayIsScopedLikeRunRead(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1")
	r := w.authorize(w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	api := w.replayAPI()
	ctx := context.Background()
	req := &pantherclawv1.ReplayDecisionRequest{TransactionId: r.TransactionID.String()}

	team := w.teamOfAgent()
	owner := api.as("owner", w.org, td.KindUser, td.Binding{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeTeam, ID: team}})
	if res, err := owner.ReplayDecision(ctx, req); err != nil || !res.GetReproduced() {
		t.Fatalf("evidence.read on the agent's team: %v, %v", res, err)
	}
	other := api.as("other-team", w.org, td.KindUser, td.Binding{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()}})
	_, err := other.ReplayDecision(ctx, req)
	replayCode(t, "evidence.read in another team", err, connect.CodePermissionDenied)
	viewer := api.as("viewer", w.org, td.KindUser, td.Binding{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	_, err = viewer.ReplayDecision(ctx, req)
	replayCode(t, "a viewer", err, connect.CodePermissionDenied)

	stranger := ids.New[ids.Org]()
	exec(t, w.pool, stranger, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'globex')", stranger)
	intruder := api.as("intruder", stranger, td.KindUser, td.Binding{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: stranger.UUID()}})
	_, err = intruder.ReplayDecision(ctx, req)
	replayCode(t, "another org's transaction", err, connect.CodeNotFound)
	_, err = intruder.ReplayDecision(ctx, &pantherclawv1.ReplayDecisionRequest{TransactionId: r.TransactionID.String(), IncludeInputs: true})
	replayCode(t, "another org's inputs", err, connect.CodeNotFound)
}

// TestHR197_ReplayIsRateLimitedPerCaller: at most 10 replays per minute per
// caller (design decision 11); another caller is not affected, and the
// limit resets after the minute.
func TestHR197_ReplayIsRateLimitedPerCaller(t *testing.T) {
	w := newWorld(t)
	w.keepInputs()
	w.refundable("ch_1")
	r := w.authorize(w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	api := w.replayAPI()
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	ctx := context.Background()
	req := &pantherclawv1.ReplayDecisionRequest{TransactionId: r.TransactionID.String()}
	first := api.as("first", w.org, td.KindUser, td.Binding{Role: td.RoleAuditor, Scope: org})
	for i := range evapp.ReplaysPerMinute {
		if _, err := first.ReplayDecision(ctx, req); err != nil {
			t.Fatalf("replay %d: %v", i+1, err)
		}
	}
	_, err := first.ReplayDecision(ctx, req)
	replayCode(t, "the 11th replay in a minute", err, connect.CodeResourceExhausted)
	second := api.as("second", w.org, td.KindUser, td.Binding{Role: td.RoleAuditor, Scope: org})
	if _, err := second.ReplayDecision(ctx, req); err != nil {
		t.Fatalf("another caller: %v", err)
	}
	api.clk.Advance(time.Minute)
	if _, err := first.ReplayDecision(ctx, req); err != nil {
		t.Fatalf("after the minute: %v", err)
	}
}
