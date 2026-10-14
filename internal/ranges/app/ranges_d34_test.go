// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// D34 (a): only agent.* and wait steps that expect a decision outcome are
// derived from the cited transaction. A person step, a replay at the
// target and a reason that is any reason of the decision record PASS with
// no MISMATCH.
func TestD34_OnlyDecisionStepsAreDerivedFromTheirTransaction(t *testing.T) {
	w := newWorld(t, billing.Business, td.RoleAgentOwner)
	r := w.start(t, decl("RT-008", domain.TierCommunity, "boundary"), decl("RT-036", domain.TierBusiness, "boundary"),
		decl("RT-020", domain.TierCommunity, "boundary"))
	held := w.txn(t, true, "REQUIRE_APPROVAL", "REQUIRE_APPROVAL_REASON")
	original := w.txn(t, true, "ALLOW", "GRANT_ALLOWS")
	two := ids.NewV7()
	w.f.txns[two] = domain.TransactionRecord{
		ID: two, Agent: w.agent, Simulated: true, Created: time.Now().Add(time.Second), Decision: "DENY", Reason: "R", Reasons: []string{"R", "X2"},
	}
	// RT-008: the person approves the held action: expected ALLOW, observed
	// by the runner, citing the transaction that was HELD.
	res, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-008", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "approve", Kind: "person.approve", Expect: allow, Observed: allow, Transaction: uid(held)}},
	})
	if err != nil || res.Verdict != domain.Pass || res.Steps[0].ObservedBy != domain.Client || res.Steps[0].Mismatch {
		t.Fatalf("person.approve: %+v, %v", res, err)
	}
	// RT-036: TARGET_REFUSED with a code, citing the original transaction.
	refused := domain.Expect{Outcome: domain.OutcomeTargetRefused, Code: "replayed"}
	res, err = w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-036", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "replay", Kind: "target.replay", Expect: refused, Observed: refused, Transaction: uid(original)}},
	})
	if err != nil || res.Verdict != domain.Pass || res.Steps[0].ObservedBy != domain.Client || res.Steps[0].Mismatch {
		t.Fatalf("target.replay: %+v, %v", res, err)
	}
	// RT-020: an agent.call expecting a reason that is the decision's second
	// reason, and a code that the server ignores.
	want := domain.Expect{Outcome: domain.OutcomeDeny, Reason: "X2", Code: "ignored"}
	res, err = w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-020", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "call", Kind: "agent.call", Expect: want, Observed: domain.Expect{Outcome: domain.OutcomeDeny, Reason: "X2"}, Transaction: uid(two)}},
	})
	if err != nil || res.Verdict != domain.Pass || res.Steps[0].ObservedBy != domain.Server || res.Steps[0].Mismatch {
		t.Fatalf("agent.call: %+v, %v", res, err)
	}
}

// D34 (b): a transaction backs the steps of one scenario per range.
func TestD34_ATransactionBacksOneScenarioPerRange(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"), decl("RT-002", domain.TierCommunity, "boundary"))
	tx := w.txn(t, true, "DENY", "DESTINATION_NOT_GRANTED")
	two := domain.StepInput{ID: "retry", Kind: "agent.call", Expect: deny, Observed: deny, Transaction: uid(tx)}
	if _, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Fail,
		Steps: []domain.StepInput{step("call", deny, deny, uid(tx)), two},
	}); err != nil {
		t.Fatalf("two steps of one scenario citing it: %v", err)
	}
	_, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-002", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{step("call", deny, deny, uid(tx))},
	})
	if !errors.Is(err, app.ErrRecord) {
		t.Fatalf("a second scenario citing it: %v, want RANGE_RECORD_INVALID", err)
	}
	// A reference the runner observed counts too.
	r2 := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"), decl("RT-002", domain.TierCommunity, "boundary"))
	tx2 := w.txn(t, true, "DENY", "X")
	person := func() app.RecordInput {
		return app.RecordInput{
			Range: r2.ID, Digest: hexA, Verdict: domain.Pass,
			Steps: []domain.StepInput{{ID: "p", Kind: "person.decline", Expect: allow, Observed: allow, Transaction: uid(tx2)}},
		}
	}
	in := person()
	in.Scenario = "RT-001"
	if _, err := w.svc.RecordResult(w.ctx, in); err != nil {
		t.Fatal(err)
	}
	in = person()
	in.Scenario = "RT-002"
	if _, err := w.svc.RecordResult(w.ctx, in); !errors.Is(err, app.ErrRecord) {
		t.Fatalf("a reference reused: %v", err)
	}
}

// D34 (c): a probe step names the result it is based on; the report must
// have it and it must be a blocked or reachable observation.
func TestD34_AProbeStepNeedsTheNamedResultOfItsReport(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-014", domain.TierCommunity, "boundary"), decl("RT-015", domain.TierCommunity, "boundary"),
		decl("RT-016", domain.TierCommunity, "boundary"), decl("RT-017", domain.TierCommunity, "boundary"))
	report := ids.NewV7()
	w.f.probes[report] = domain.ProbeRecord{
		ID: report, Agent: w.agent, Recorded: time.Now().Add(time.Second),
		Results: map[string]string{"dns_external": "blocked", "icmp": "error"},
	}
	blocked := domain.Expect{Outcome: domain.OutcomeBlocked}
	rec := func(scenario, kind string) error {
		_, err := w.svc.RecordResult(w.ctx, app.RecordInput{
			Range: r.ID, Scenario: scenario, Digest: hexA, Verdict: domain.Pass,
			Steps: []domain.StepInput{{ID: "p", Kind: "sandbox.probe", ProbeKind: kind, Expect: blocked, Observed: blocked, Probe: uid(report)}},
		})
		return err
	}
	if err := rec("RT-014", "dns_external"); err != nil {
		t.Fatalf("a named, blocked result: %v", err)
	}
	for scenario, kind := range map[string]string{"RT-015": "", "RT-016": "metadata", "RT-017": "icmp"} {
		if err := rec(scenario, kind); !errors.Is(err, app.ErrRecord) {
			t.Errorf("probe kind %q: %v, want RANGE_RECORD_INVALID", kind, err)
		}
	}
}

// D34 (d): a PASS records exactly step_count steps; a FAIL may record
// fewer, and a FAIL whose recorded steps all matched stays a FAIL.
func TestD34_APassRecordsEveryStep(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	one := decl("RT-001", domain.TierCommunity, "boundary")
	one.StepCount = 2
	other := decl("RT-002", domain.TierCommunity, "boundary")
	other.StepCount = 2
	r := w.start(t, one, other)
	a, b := step("a", allow, allow, nil), step("b", allow, allow, nil)
	if _, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{a},
	}); !errors.Is(err, app.ErrSteps) {
		t.Fatalf("a PASS with 1 of 2 steps: %v", err)
	}
	if res, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Fail,
		Steps: []domain.StepInput{a},
	}); err != nil || res.Verdict != domain.Fail {
		t.Fatalf("a FAIL with 1 of 2 steps that all matched: %+v, %v, want FAIL", res, err)
	}
	if res, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-002", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{a, b},
	}); err != nil || res.Verdict != domain.Pass {
		t.Fatalf("a PASS with 2 of 2 steps: %+v, %v", res, err)
	}
}

// A step needs its kind.
func TestD34_AStepNeedsItsKind(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"))
	_, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "a", Expect: allow, Observed: allow}},
	})
	if !errors.Is(err, app.ErrSteps) {
		t.Fatalf("a step without a kind: %v", err)
	}
}

// D34 (e): declarations are checked up front.
func TestD34_DeclarationsAreCheckedUpFront(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	good := decl("RT-001", domain.TierCommunity, "boundary")
	bad := map[string]func(*domain.Scenario){
		"suite":      func(s *domain.Scenario) { s.Suite = "other" },
		"id":         func(s *domain.Scenario) { s.ID = "RT-1" },
		"digest":     func(s *domain.Scenario) { s.Digest = "AAAA" },
		"long title": func(s *domain.Scenario) { s.Title = strings.Repeat("x", 201) },
		"step count": func(s *domain.Scenario) { s.StepCount = 0 },
		"too many":   func(s *domain.Scenario) { s.StepCount = 41 },
	}
	for name, mutate := range bad {
		s := good
		mutate(&s)
		_, err := w.svc.StartRange(w.ctx, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{s}, RunnerVersion: "t"})
		if !errors.Is(err, app.ErrScenarios) {
			t.Errorf("%s: %v, want INVALID_SCENARIOS", name, err)
		}
	}
}
