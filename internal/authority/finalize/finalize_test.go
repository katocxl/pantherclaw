// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

func scenario(t *testing.T) (*pipelinetest.Scenario, gdomain.Grant, ids.UUID) {
	t.Helper()
	s := pipelinetest.NewScenario(t, nil)
	g := s.Grant(pipelinetest.RootBounds, s.Alice)
	return s, g, s.Run(g.ID, s.Alice)
}

func holdOver50(t *testing.T, s *pipelinetest.Scenario) {
	t.Helper()
	if err := s.W.SetPolicy([]pdomain.Rule{{
		ID: "hold", Kind: pdomain.RequireApproval, Summary: "over 50 needs approval",
		Operations: []string{"payments.refund.create"}, When: `action.params.amount > money("50", "USD")`, Reason: "REFUND_OVER_50",
		Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}}, nil); err != nil {
		t.Fatal(err)
	}
}

func decisive(r finalize.Result) string {
	for _, x := range r.Reasons {
		if x.Decisive {
			return x.Code
		}
	}
	return ""
}

func TestHR005_AFinalizedActionNeverGetsASecondPermit(t *testing.T) {
	s, _, run := scenario(t)
	req := s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00"))
	first := s.Authorize(req)
	if first.Decision != adomain.Allow || first.Permit == "" || first.Receipt == "" {
		t.Fatalf("first: %+v", first)
	}
	again := s.Authorize(req)
	if !again.Repeat || again.Permit != "" || again.Decision != adomain.Allow || again.Receipt != first.Receipt ||
		again.TransactionID != first.TransactionID {
		t.Fatalf("a repeat must return the stored decision and receipt, never a permit: %+v", again)
	}

	// Concurrent repeats of a new action: exactly one permit.
	req = s.Request(run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`)
	var wg sync.WaitGroup
	var mu sync.Mutex
	permits := 0
	for range 50 {
		wg.Go(func() {
			res, err := s.Authority.Authorize(context.Background(), s.Gateway, req)
			if err != nil {
				t.Error(err)
				return
			}
			if res.Permit != "" {
				mu.Lock()
				permits++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if permits != 1 {
		t.Fatalf("%d permits for one (run, action), want exactly 1", permits)
	}
}

func TestHR006_ATamperedActionIsDeniedAndClosesItsTransaction(t *testing.T) {
	s, _, run := scenario(t)
	holdOver50(t, s)
	act := ids.NewV7()
	held := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "85.00")))
	if held.Decision != adomain.RequireApproval {
		t.Fatalf("held: %+v", held)
	}
	changed := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "95.00")))
	if changed.Decision != adomain.Deny || decisive(changed) != adomain.ReasonActionTampered {
		t.Fatalf("a changed action under the same id: %+v", changed)
	}
	if evs := s.W.SecurityEvents(); len(evs) != 1 || !strings.Contains(evs[0], "action_tampered") {
		t.Fatalf("security events %v", evs)
	}
	original := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "85.00")))
	if original.Decision != adomain.Deny || !original.Repeat {
		t.Fatalf("the held action cannot be resumed after tampering: %+v", original)
	}

	// A final ALLOW is not changed by a tamper attempt.
	act = ids.NewV7()
	ok := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_2", "10.00")))
	if ok.Decision != adomain.Allow {
		t.Fatalf("allow: %+v", ok)
	}
	if r := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_2", "11.00"))); r.Decision != adomain.Deny || r.Permit != "" {
		t.Fatalf("tamper after allow: %+v", r)
	}
	if r := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_2", "10.00"))); r.Decision != adomain.Allow || !r.Repeat {
		t.Fatalf("the stored allow stays: %+v", r)
	}
}

func TestHR006_DenyIsTerminalCannotAuthorizeIsRetried(t *testing.T) {
	s, g, run := scenario(t)
	act := ids.NewV7()
	denied := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "125.00")))
	if denied.Decision != adomain.Deny {
		t.Fatalf("over the grant: %+v", denied)
	}
	wider := g
	wider.Revision = 2
	wider.Bounds.Params = nil
	s.W.Grants.Put(wider)
	if r := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "125.00"))); r.Decision != adomain.Deny || !r.Repeat {
		t.Fatalf("a DENY is terminal for its (run, action): %+v", r)
	}

	act = ids.NewV7()
	missing := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_9", "10.00")))
	if missing.Decision != adomain.CannotAuthorize || missing.Evaluation != 1 {
		t.Fatalf("missing fact: %+v", missing)
	}
	s.Refundable("ch_9")
	retried := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_9", "10.00")))
	if retried.Decision != adomain.Allow || retried.Evaluation != 2 || retried.TransactionID != missing.TransactionID || retried.Receipt == missing.Receipt {
		t.Fatalf("CANNOT_AUTHORIZE is retried as a new evaluation of the same transaction: %+v", retried)
	}
}

func TestT023_EvaluationsPerTransactionAreCapped(t *testing.T) {
	s, _, run := scenario(t)
	req := s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_9", "10.00")) // fact missing: OPEN
	for i := 1; i <= finalize.MaxEvaluations; i++ {
		if r := s.Authorize(req); r.Evaluation != i || r.Repeat {
			t.Fatalf("evaluation %d: %+v", i, r)
		}
	}
	if r := s.Authorize(req); !r.Repeat || r.Evaluation != finalize.MaxEvaluations {
		t.Fatalf("past the cap the stored decision comes back: %+v", r)
	}
}

func TestHR007_ConcurrentIdenticalActionsGetOnePermit(t *testing.T) {
	s, _, run := scenario(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	permits, parked := 0, 0
	for range 20 {
		wg.Go(func() {
			r, err := s.Authority.Authorize(context.Background(), s.Gateway, s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case r.Permit != "":
				permits++
			case decisive(r) == pipeline.ReasonReconciliation:
				parked++
			default:
				t.Errorf("unexpected %s %s", r.Decision, decisive(r))
			}
		})
	}
	wg.Wait()
	if permits != 1 || parked != 19 {
		t.Fatalf("%d permits and %d parked, want 1 and 19", permits, parked)
	}
}

func TestHR007_RepeatProtectionFollowsTheOutcome(t *testing.T) {
	s, g, run := scenario(t)
	g.Revision, g.ExpiresAt = 2, pipelinetest.Start.Add(7*24*time.Hour) // outlives the windows below
	s.W.Grants.Put(g)
	ctx := context.Background()
	refund := func() finalize.Result {
		return s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	}
	first := refund()
	if r := refund(); decisive(r) != pipeline.ReasonReconciliation {
		t.Fatalf("a repeat while the first is issued: %s", decisive(r))
	}
	// Failed at the target: the claim is released.
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, first.PermitID, first.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: first.PermitID, Outcome: finalize.Failed}); err != nil {
		t.Fatal(err)
	}
	second := refund()
	if second.Permit == "" {
		t.Fatalf("after a failure the action may be tried again: %s", decisive(second))
	}
	// Accepted: repeats wait for the window.
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, second.PermitID, second.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: second.PermitID, Outcome: finalize.Accepted}); err != nil {
		t.Fatal(err)
	}
	if r := refund(); decisive(r) != pipeline.ReasonReconciliation {
		t.Fatalf("a repeat after a success inside the window: %s", decisive(r))
	}
	s.W.Advance(25 * time.Hour)
	s.Refundable("ch_1")
	third := refund()
	if third.Permit == "" {
		t.Fatalf("after the window: %s", decisive(third))
	}
	// Unknown: blocked until reconciled (M7).
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, third.PermitID, third.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: third.PermitID, Outcome: finalize.Unknown}); err != nil {
		t.Fatal(err)
	}
	s.W.Advance(48 * time.Hour)
	s.Refundable("ch_1")
	if r := refund(); decisive(r) != pipeline.ReasonReconciliation {
		t.Fatalf("an UNKNOWN outcome must block its repeat whatever the window: %s", decisive(r))
	}
}

func TestHR003_ExpiredPermitsReleaseUnknownOnesHold(t *testing.T) {
	s, g, run := scenario(t)
	lim, err := gdomain.DecodeLimits([]byte(`{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.*"], "currency": "USD", "limit": "100", "period": "none"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g.Revision, g.Limits = 2, lim
	s.W.Grants.Put(g)
	ctx := context.Background()
	a := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "60.00")))
	if a.Permit == "" {
		t.Fatalf("first: %s", decisive(a))
	}
	if r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_2", "60.00"))); decisive(r) != gdomain.ReasonBudgetExhausted {
		t.Fatalf("the reservation counts: %s", decisive(r))
	}
	s.W.Advance(10 * time.Second) // the permit expired unused
	if rel, _, err := s.Authority.Sweep(ctx, s.Org, 30*time.Second); err != nil || rel != 1 {
		t.Fatalf("sweep released %d, %v", rel, err)
	}
	b := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_2", "60.00")))
	if b.Permit == "" {
		t.Fatalf("after the release: %s", decisive(b))
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, b.PermitID, b.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	s.W.Advance(time.Minute)
	if _, unk, _ := s.Authority.Sweep(ctx, s.Org, 30*time.Second); unk != 1 {
		t.Fatal("a stale DISPATCHING permit becomes UNKNOWN")
	}
	if st := s.W.PermitState(b.PermitID); st != "UNKNOWN" {
		t.Fatalf("permit %s", st)
	}
	if r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_3", "60.00"))); decisive(r) != gdomain.ReasonBudgetExhausted {
		t.Fatalf("an UNKNOWN keeps its reservation (F115): %s", decisive(r))
	}
}

func TestHR001_BeginDispatchIsTheCommitPoint(t *testing.T) {
	s, g, run := scenario(t)
	ctx := context.Background()
	issue := func() finalize.Result {
		r := s.Authorize(s.Request(run, ids.NewV7(), "get_refund", `{"refund":"re_1"}`))
		if r.Permit == "" {
			t.Fatalf("no permit: %s", decisive(r))
		}
		return r
	}
	a := issue()
	if _, err := s.Authority.BeginDispatch(ctx, finalize.Gateway{ID: "other", Org: s.Org}, a.PermitID, a.Epoch, finalize.Outbound{}); !errors.Is(err, finalize.ErrPermitUnknown) {
		t.Fatalf("another gateway's permit: %v", err)
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, a.PermitID, a.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, a.PermitID, a.Epoch, finalize.Outbound{}); !errors.Is(err, finalize.ErrPermitUsed) {
		t.Fatalf("a permit is single use: %v", err)
	}
	b := issue()
	s.W.Cont.Epoch++ // a revocation elsewhere
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, b.PermitID, b.Epoch, finalize.Outbound{}); !errors.Is(err, finalize.ErrEpochStale) {
		t.Fatalf("a permit from before a containment change: %v", err)
	}
	c := issue()
	s.W.Advance(6 * time.Second)
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, c.PermitID, c.Epoch, finalize.Outbound{}); !errors.Is(err, finalize.ErrPermitExpired) {
		t.Fatalf("an expired permit: %v", err)
	}
	_ = g
}

// TestF193_6_StaleOrChangedApprovalFails: a held refund resubmitted with a
// changed amount is denied as tampered; a held refund whose grant is then
// narrowed is decided again under the new revision, with a new decision
// basis that an approval of the old one (M5) cannot match.
func TestF193_6_StaleOrChangedApprovalFails(t *testing.T) {
	s, g, run := scenario(t)
	holdOver50(t, s)
	act := ids.NewV7()
	held := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "85.00")))
	if held.Decision != adomain.RequireApproval || decisive(held) != "REFUND_OVER_50" {
		t.Fatalf("held: %+v", held)
	}
	if r := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_1", "84.00"))); decisive(r) != adomain.ReasonActionTampered {
		t.Fatalf("changed amount: %s", decisive(r))
	}

	act = ids.NewV7()
	req := s.Request(run, act, "create_refund", pipelinetest.Refund("ch_2", "85.00"))
	held = s.Authorize(req)
	narrowed := g
	narrowed.Revision = 2
	narrowed.Bounds.Params = map[string]map[string]gdomain.ParamBound{"payments.refund.create": {"amount": {Max: gdomain.Amounts{"USD": "80.00"}}}}
	s.W.Grants.Put(narrowed)
	again := s.Authorize(req)
	if again.Decision != adomain.Deny || decisive(again) != gdomain.ReasonGrantLimitExceeded || again.BasisDigest == held.BasisDigest {
		t.Fatalf("re-decided: %s %s (basis changed %v)", again.Decision, decisive(again), again.BasisDigest != held.BasisDigest)
	}
}

// TestReceiptRecordsTheDecision: the decision receipt holds the decision,
// its explanation and basis, and never claims dispatch or an effect (the
// property itself is TestINV11 in test/invariants).
func TestReceiptRecordsTheDecision(t *testing.T) {
	s, _, run := scenario(t)
	r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	var receipt finalize.DecisionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(r.Receipt), &receipt); err != nil {
		t.Fatal(err)
	}
	p := receipt.Pap
	if p.Kind != "decision" || p.Decision != adomain.Allow || p.Txn != r.TransactionID.String() || p.BasisDigest == "" ||
		p.Act != r.ActionHash || len(p.Checklist) == 0 || !p.Checklist[0].Decisive || len(p.Budgets) != 0 {
		t.Fatalf("receipt %+v", p)
	}
	raw := string(pipelinetest.Payload(r.Receipt))
	for _, forbidden := range []string{"accepted", "dispatched", "effect", "outcome"} {
		if strings.Contains(raw, `"`+forbidden) {
			t.Fatalf("a decision receipt mentions %q: %s", forbidden, raw)
		}
	}
}

// TestHR049_CountersAreReservedInTheFinalization: "one refund per charge
// per day" holds under concurrency, because the counter row is reserved in
// the finalization, never checked in CEL.
func TestHR049_CountersAreReservedInTheFinalization(t *testing.T) {
	s, g, run := scenario(t)
	lim, err := gdomain.DecodeLimits([]byte(`{"counters": [{"id": "per_charge", "operations": ["payments.refund.create"], "key": "target", "window": "day", "max": "1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	g.Revision, g.Limits = 2, lim
	s.W.Grants.Put(g)
	var wg sync.WaitGroup
	var mu sync.Mutex
	permits := 0
	for i := range 20 {
		amount := "1" + strings.Repeat("0", i%3) + ".00" // different refunds of one charge
		req := s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", amount))
		wg.Go(func() {
			if r, err := s.Authority.Authorize(context.Background(), s.Gateway, req); err == nil && r.Permit != "" {
				mu.Lock()
				permits++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if permits != 1 {
		t.Fatalf("%d refunds of one charge were permitted, the counter allows 1", permits)
	}
	if r := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_2", "5.00"))); r.Permit == "" {
		t.Fatalf("another charge has its own counter: %s", decisive(r))
	}
}
