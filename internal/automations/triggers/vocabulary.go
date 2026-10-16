// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// The platform-event vocabulary (D18): the only names an event or
// threshold trigger may name, and the feed entries each one means.
//
//	action.decided     receipt.decision (any decision)
//	action.held        receipt.decision with decision HOLD
//	action.denied      receipt.decision with decision DENY
//	effect.recorded    receipt.effect
//	run.ended          audit.run.ended
//	grant.issued       audit.grant.issued
//	grant.revoked      audit.grant.revoked
//	coverage.lost      coverage.invalidation, or coverage.snapshot whose
//	                   state fell below its previous state
//	alert.raised       reflex.alert (written once, when an alert is raised)
//	incident.opened    reflex.incident whose state is OPEN (opened or
//	                   reopened)
//	case.closed        reflex.case whose case entry moves the case to CLOSED
//	agent.discovered   audit.agent.discovered (D18a)
//	approval.expired   audit.approval.expired
//	automation.finished audit.automation.execution_finished (the engine, D24)
const (
	VocabActionDecided      = "action.decided"
	VocabActionHeld         = "action.held"
	VocabActionDenied       = "action.denied"
	VocabEffectRecorded     = "effect.recorded"
	VocabRunEnded           = "run.ended"
	VocabGrantIssued        = "grant.issued"
	VocabGrantRevoked       = "grant.revoked"
	VocabCoverageLost       = "coverage.lost"
	VocabAlertRaised        = "alert.raised"
	VocabIncidentOpened     = "incident.opened"
	VocabCaseClosed         = "case.closed"
	VocabAgentDiscovered    = "agent.discovered"
	VocabApprovalExpired    = "approval.expired"
	VocabAutomationFinished = "automation.finished"
)

// Ledger kinds read by the vocabulary.
const (
	kindDecision     = "receipt.decision"
	kindEffect       = "receipt.effect"
	kindCoverageSnap = "coverage.snapshot"
	kindCoverageInv  = "coverage.invalidation"
	kindAlert        = "reflex.alert"
	kindIncident     = "reflex.incident"
	kindCase         = "reflex.case"
)

var vocabulary = []string{
	VocabActionDecided, VocabActionHeld, VocabActionDenied, VocabEffectRecorded, VocabRunEnded, VocabGrantIssued,
	VocabGrantRevoked, VocabCoverageLost, VocabAlertRaised, VocabIncidentOpened, VocabCaseClosed,
	VocabAgentDiscovered, VocabApprovalExpired, VocabAutomationFinished,
}

// Vocabulary lists the event names.
func Vocabulary() []string { return slices.Clone(vocabulary) }

// KnownEvent reports whether name is in the vocabulary.
func KnownEvent(name string) bool { return slices.Contains(vocabulary, name) }

// coverageRank orders coverage states; a lower rank is less coverage.
var coverageRank = map[string]int{"UNKNOWN": 0, "OBSERVE_ONLY": 1, "PARTIAL": 2, "ENFORCED": 3}

// Facts are what Means needs beyond the event itself.
type Facts struct {
	// CaseClosed: the event is a reflex.case entry that closes its case.
	CaseClosed bool
}

// Means reports whether event e is an occurrence of vocabulary name.
func Means(name string, e feed.Event, f Facts) bool {
	switch name {
	case VocabActionDecided:
		return e.Kind == kindDecision && e.Decision != ""
	case VocabActionHeld:
		return e.Kind == kindDecision && e.Decision == "HOLD"
	case VocabActionDenied:
		return e.Kind == kindDecision && e.Decision == "DENY"
	case VocabEffectRecorded:
		return e.Kind == kindEffect
	case VocabRunEnded:
		return e.Kind == "audit.run.ended"
	case VocabGrantIssued:
		return e.Kind == "audit.grant.issued"
	case VocabGrantRevoked:
		return e.Kind == "audit.grant.revoked"
	case VocabCoverageLost:
		if e.Kind == kindCoverageInv {
			return true
		}
		if e.Kind != kindCoverageSnap {
			return false
		}
		prev, ok := coverageRank[e.Attrs["previous_state"]]
		cur, ok2 := coverageRank[e.Attrs["state"]]
		return ok && ok2 && cur < prev
	case VocabAlertRaised:
		return e.Kind == kindAlert
	case VocabIncidentOpened:
		return e.Kind == kindIncident && e.Outcome == "OPEN"
	case VocabCaseClosed:
		return e.Kind == kindCase && f.CaseClosed
	case VocabAgentDiscovered:
		return e.Kind == "audit.agent.discovered"
	case VocabApprovalExpired:
		return e.Kind == "audit.approval.expired"
	case VocabAutomationFinished:
		return e.Kind == "audit.automation.execution_finished"
	}
	return false
}

// eventField reads a parameter source path of an event (ParamSpec.from for
// event and threshold triggers): kind, actor_type, actor_id, decision,
// reason, operation, mode, outcome, environment, destination_class,
// subjects.<type> (its first id) or attrs.<key>. ok is false when the
// event has no such value.
func eventField(e feed.Event, path string) (string, bool) {
	if t, ok := strings.CutPrefix(path, "subjects."); ok {
		for _, s := range e.Subjects {
			if string(s.Type) == t {
				return s.ID, true
			}
		}
		return "", false
	}
	if k, ok := strings.CutPrefix(path, "attrs."); ok {
		v, ok := e.Attrs[k]
		return v, ok
	}
	var v string
	switch path {
	case "kind":
		v = e.Kind
	case "actor_type":
		v = e.ActorType
	case "actor_id":
		v = e.ActorID
	case "decision":
		v = e.Decision
	case "reason":
		v = e.Reason
	case "operation":
		v = e.Operation
	case "mode":
		v = e.Mode
	case "outcome":
		v = e.Outcome
	case "environment":
		v = e.Environment
	case "destination_class":
		v = e.DestinationClass
	default:
		return "", false
	}
	return v, v != ""
}
