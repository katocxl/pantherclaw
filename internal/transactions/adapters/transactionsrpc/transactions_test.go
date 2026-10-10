// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package transactionsrpc

import (
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// TestEveryStateHasItsProtoValue: each execution state, effect state,
// level, decision, reconciliation kind and state, and outcome maps to its
// own value, never to UNSPECIFIED.
func TestEveryStateHasItsProtoValue(t *testing.T) {
	seen := map[pantherclawv1.ExecutionState]bool{}
	for _, s := range []domain.ExecutionState{
		domain.Requested, domain.Blocked, domain.Waiting, domain.Authorized, domain.Dispatched, domain.Accepted,
		domain.Failed, domain.Canceled,
	} {
		p := TransactionProto(app.Summary{Execution: s}).GetExecutionState()
		if p == pantherclawv1.ExecutionState_EXECUTION_STATE_UNSPECIFIED || seen[p] {
			t.Errorf("execution state %s: %v", s, p)
		}
		seen[p] = true
	}
	effects := map[pantherclawv1.EffectState]bool{}
	for _, s := range []domain.EffectState{
		domain.Confirmed, domain.NoneConfirmed, domain.Partial, domain.PropagationPending, domain.Conflicting,
		domain.Unverifiable, domain.Unknown, domain.Compensated,
	} {
		p := effectState(s)
		if p == pantherclawv1.EffectState_EFFECT_STATE_UNSPECIFIED || effects[p] {
			t.Errorf("effect state %s: %v", s, p)
		}
		effects[p] = true
	}
	if effectState("") != pantherclawv1.EffectState_EFFECT_STATE_UNSPECIFIED {
		t.Error("no effect receipt yet must stay unspecified")
	}
	for _, l := range []defs.Level{defs.LevelAcceptance, defs.LevelFollowUp, defs.LevelDomainEffect, defs.LevelDownstream} {
		if level(string(l)) == pantherclawv1.VerificationLevel_VERIFICATION_LEVEL_UNSPECIFIED {
			t.Errorf("level %s", l)
		}
	}
	for _, d := range []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS", "REQUIRE_APPROVAL", "REQUIRE_STEP_UP", "DENY", "CANNOT_AUTHORIZE"} {
		if TransactionProto(app.Summary{Decision: d}).GetDecision() == pantherclawv1.Decision_DECISION_UNSPECIFIED {
			t.Errorf("decision %s", d)
		}
	}
	for _, o := range []string{"accepted", "failed", "unknown", "delegated"} {
		if outcome(o) == pantherclawv1.Outcome_OUTCOME_UNSPECIFIED {
			t.Errorf("outcome %s", o)
		}
	}
	for _, k := range []domain.TaskKind{domain.KindUnknownOutcome, domain.KindConflictingEffect} {
		for _, s := range []domain.TaskState{domain.TaskOpen, domain.TaskOccurred, domain.TaskNotOccurred} {
			p := ReconciliationProto(app.Reconciliation{Kind: k, State: s})
			if p.GetKind() == pantherclawv1.ReconciliationKind_RECONCILIATION_KIND_UNSPECIFIED ||
				p.GetState() == pantherclawv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED {
				t.Errorf("reconciliation %s %s: %v %v", k, s, p.GetKind(), p.GetState())
			}
		}
	}
	for _, k := range []domain.LinkKind{domain.LinkCompensates, domain.LinkRecovers} {
		if linkKind(k) == pantherclawv1.LinkKind_LINK_KIND_UNSPECIFIED {
			t.Errorf("link kind %s", k)
		}
		if linkKindOf(linkKind(k)) != k {
			t.Errorf("link kind %s does not round-trip", k)
		}
	}
	for _, k := range []domain.TaskKind{domain.KindUnknownOutcome, domain.KindConflictingEffect} {
		if taskKindOf(ReconciliationProto(app.Reconciliation{Kind: k}).GetKind()) != k {
			t.Errorf("reconciliation kind %s does not round-trip", k)
		}
	}
	if s := integrity(app.Integrity{}).GetStatus(); s != pantherclawv1.IntegrityStatus_INTEGRITY_STATUS_PENDING {
		t.Errorf("an entry not yet chained: %v", s)
	}
	if s := integrity(app.Integrity{Seq: 7}).GetStatus(); s != pantherclawv1.IntegrityStatus_INTEGRITY_STATUS_CHAINED {
		t.Errorf("a chained entry: %v", s)
	}
}
