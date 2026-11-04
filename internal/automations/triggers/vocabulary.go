// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// The platform-event vocabulary (D18): the only names an event or
// threshold trigger may name, and the feed entries each one means.
//
//	action.decided     receipt.decision (any decision)
//	action.held        receipt.decision presented as a hold: a receipt holds
//	                   REQUIRE_APPROVAL or REQUIRE_STEP_UP, never HOLD
//	action.denied      receipt.decision with decision DENY
//	effect.recorded    receipt.effect
//	run.ended          audit.run.ended
//	grant.issued       audit.grant.issued
//	grant.revoked      audit.grant.revoked
//	coverage.lost      coverage.invalidation, or coverage.snapshot whose
//	                   state fell below its previous state
//	alert.raised       reflex.alert (written once, when an alert is raised),
//	                   on any basis
//	alert.inferred     reflex.alert whose basis is an inference or hypothesis
//	                   (G0 M27 D500); no contain step may start from it
//	incident.opened    reflex.incident whose state is OPEN (opened or
//	                   reopened)
//	case.closed        reflex.case whose case entry moves the case to CLOSED
//	agent.discovered   audit.agent.discovered (D18a)
//	agent.discovery_changed  audit.agent.discovery_changed (G0 M17 D116)
//	agent.discovery_vanished audit.agent.discovery_vanished (G0 M17 D114)
//	approval.expired   audit.approval.expired
//	automation.finished audit.automation.execution_finished (the engine, D24)
const (
	VocabActionDecided      = "action.decided"
	VocabActionHeld         = "action.held"
	VocabActionDenied       = "action.denied"
	VocabEffectRecorded     = "effect.recorded"
	VocabRunEnded           = auditkind.RunEnded
	VocabGrantIssued        = auditkind.GrantIssued
	VocabGrantRevoked       = auditkind.GrantRevoked
	VocabCoverageLost       = "coverage.lost"
	VocabAlertRaised        = "alert.raised"
	VocabAlertInferred      = "alert.inferred"
	VocabIncidentOpened     = "incident.opened"
	VocabCaseClosed         = "case.closed"
	VocabAgentDiscovered    = auditkind.AgentDiscovered
	VocabDiscoveryChanged   = auditkind.AgentDiscoveryChanged
	VocabDiscoveryVanished  = auditkind.AgentDiscoveryVanished
	VocabApprovalExpired    = auditkind.ApprovalExpired
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

// attrBasis is the event attribute and trigger detail naming a signal's
// basis.
const attrBasis = "basis"

var vocabulary = []string{
	VocabActionDecided, VocabActionHeld, VocabActionDenied, VocabEffectRecorded, VocabRunEnded, VocabGrantIssued,
	VocabGrantRevoked, VocabCoverageLost, VocabAlertRaised, VocabIncidentOpened, VocabCaseClosed,
	VocabAgentDiscovered, VocabApprovalExpired, VocabAutomationFinished, VocabDiscoveryChanged, VocabDiscoveryVanished,
	VocabAlertInferred,
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
		return e.Kind == kindDecision && adomain.Decision(e.Decision).Presentation() == adomain.PresentHold
	case VocabActionDenied:
		return e.Kind == kindDecision && e.Decision == "DENY"
	case VocabEffectRecorded:
		return e.Kind == kindEffect
	case VocabRunEnded:
		return e.Kind == "audit."+auditkind.RunEnded
	case VocabGrantIssued:
		return e.Kind == "audit."+auditkind.GrantIssued
	case VocabGrantRevoked:
		return e.Kind == "audit."+auditkind.GrantRevoked
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
	case VocabAlertInferred:
		return e.Kind == kindAlert && inferred(e)
	case VocabIncidentOpened:
		return e.Kind == kindIncident && e.Outcome == "OPEN"
	case VocabCaseClosed:
		return e.Kind == kindCase && f.CaseClosed
	case VocabAgentDiscovered:
		return e.Kind == "audit."+auditkind.AgentDiscovered
	case VocabDiscoveryChanged:
		return e.Kind == "audit."+auditkind.AgentDiscoveryChanged
	case VocabDiscoveryVanished:
		return e.Kind == "audit."+auditkind.AgentDiscoveryVanished
	case VocabApprovalExpired:
		return e.Kind == "audit."+auditkind.ApprovalExpired
	case VocabAutomationFinished:
		return e.Kind == "audit."+auditkind.AutomationExecutionFinished
	}
	return false
}

// inferred reports a Reflex alert or incident that rests on an inference
// (G0 M27 D500). An alert with no readable basis counts as one; an incident
// names a basis only when a signal opened it, never for a person's change.
func inferred(e feed.Event) bool {
	b, named := e.Attrs[attrBasis]
	switch e.Kind {
	case kindAlert:
		return reflexdomain.Basis(b).Inferred()
	case kindIncident:
		return named && reflexdomain.Basis(b).Inferred()
	}
	return false
}

// confirmed reports a Reflex alert or incident that is a CONFIRMED alert:
// its basis was observed or matched by a rule (G0 M27 D514). An incident a
// person changed names no basis and isn't one.
func confirmed(e feed.Event) bool {
	if e.Kind != kindAlert && e.Kind != kindIncident {
		return false
	}
	b, named := e.Attrs[attrBasis]
	return named && reflexdomain.Basis(b).Confirmed()
}

// signal reports a Reflex alert or incident.
func signal(e feed.Event) bool { return e.Kind == kindAlert || e.Kind == kindIncident }

// detailConfirmed is the trigger detail that marks a CONFIRMED alert.
const detailConfirmed = "confirmed"

// EventField reads a parameter source path of an event (ParamSpec.from for
// event and threshold triggers): kind, actor_type, actor_id, decision,
// reason, operation, mode, outcome, environment, destination_class,
// subjects.<type> (its first id) or attrs.<key>. ok is false when the
// event has no such value.
func EventField(e feed.Event, path string) (string, bool) {
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
