// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"slices"
	"strings"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Reason codes of containment controls (G0 M10 D21, HR-248).
const (
	// ReasonContained: a DENY_ALL control, or a DENY_OPERATION control of
	// the action's operation, covers the action.
	ReasonContained = "CONTAINED"
	// ReasonContainedWrites: a HOLD_WRITES control covers a non-read
	// action, which waits for a responder's approval.
	ReasonContainedWrites = "CONTAINED_WRITES"
)

// Controls of a containment control (D21).
const (
	ControlDenyAll       = "DENY_ALL"
	ControlHoldWrites    = "HOLD_WRITES"
	ControlDenyOperation = "DENY_OPERATION"
)

// Scope types of a containment control (D21).
const (
	ControlScopeAgent      = "agent"
	ControlScopeRun        = "run"
	ControlScopeGrant      = "grant"
	ControlScopeConnection = "connection"
	ControlScopeResource   = "resource"
	ControlScopePrincipal  = "principal"
)

// Control is an active containment control of the org (D21): it was not
// lifted and has not expired by the database clock when the evaluation
// read it.
type Control struct {
	ID ids.UUID
	// ScopeType is one of the ControlScope constants. ScopeID is a uuid,
	// except for a resource ("<target type>:<target id pattern>", where a
	// trailing * matches a prefix) and a principal ("user:<id>" or
	// "service_account:<id>").
	ScopeType string
	ScopeID   string
	Control   string
	// Operation is the operation a DENY_OPERATION control denies.
	Operation string
	ExpiresAt *time.Time
}

// controlled checks the org's active controls against the action (step 3):
// a DENY_ALL control or a DENY_OPERATION control of the action's operation
// on its run, agent, grant chain, connection, target or people denies it
// CONTAINED; a HOLD_WRITES control holds a non-read action for a
// responder's approval (CONTAINED_WRITES; step 8 adds the requirement)
// while reads continue. A monitor-mode route has no hold, so there a
// HOLD_WRITES control denies the write. It reports whether a control
// denied the action.
func (s *state) controlled() bool {
	denied := false
	for _, c := range s.cont.Controls {
		if !s.covers(c) {
			continue
		}
		switch c.Control {
		case ControlDenyAll:
			s.cl.add(StepContainment, adomain.Deny, ReasonContained, "containment control "+c.ID.String()+" denies every action on its "+c.ScopeType, "")
			denied = true
		case ControlDenyOperation:
			if c.Operation == s.a.Operation {
				s.cl.add(StepContainment, adomain.Deny, ReasonContained, "containment control "+c.ID.String()+" denies "+c.Operation+" on its "+c.ScopeType, "")
				denied = true
			}
		case ControlHoldWrites:
			if s.def != nil && s.def.Access == defs.AccessRead {
				continue
			}
			if s.ev.Mode == ModeMonitor || s.def == nil {
				s.cl.add(StepContainment, adomain.Deny, ReasonContainedWrites, "containment control "+c.ID.String()+" holds writes on its "+c.ScopeType+", and this route cannot hold", "")
				denied = true
				continue
			}
			s.held = append(s.held, c)
		default:
			// An unknown control fails closed.
			s.cl.add(StepContainment, adomain.Deny, ReasonContained, "containment control "+c.ID.String()+" is not understood", "")
			denied = true
		}
	}
	return denied
}

// covers reports whether a control's scope covers the action. What the
// evaluation could not establish (no run, no connection) is not covered by
// that scope; an earlier step has then already refused the action.
func (s *state) covers(c Control) bool {
	switch c.ScopeType {
	case ControlScopeRun:
		return !s.ev.RunID.IsZero() && c.ScopeID == s.ev.RunID.String()
	case ControlScopeAgent:
		return s.run != nil && c.ScopeID == s.run.AgentID.String()
	case ControlScopeGrant:
		// The grant and every grant issued under it (grant_lineage): the
		// run's chain holds the leaf and its ancestors.
		return slices.ContainsFunc(s.chain.Grants, func(g gdomain.Grant) bool { return g.ID.String() == c.ScopeID }) ||
			(s.run != nil && !s.run.GrantID.IsZero() && s.run.GrantID.String() == c.ScopeID)
	case ControlScopeConnection:
		return c.ScopeID == s.a.Connection || (s.conn != nil && c.ScopeID == s.conn.ID.String())
	case ControlScopeResource:
		return resourceMatches(c.ScopeID, s.a.Target.Type, s.a.Target.ID)
	case ControlScopePrincipal:
		if s.run == nil {
			return false
		}
		if s.run.Principal.String() == c.ScopeID || s.run.Launcher.String() == c.ScopeID {
			return true
		}
		return slices.ContainsFunc(s.run.Ancestors, func(p gdomain.Principal) bool { return p.String() == c.ScopeID })
	}
	// An unknown scope covers everything (fail closed).
	return true
}

// resourceMatches matches "<type>:<pattern>" against a target: the type
// exactly, the id exactly or, for a pattern ending in *, by prefix.
func resourceMatches(scope, typ, id string) bool {
	t, pattern, ok := strings.Cut(scope, ":")
	if !ok || t != typ {
		return false
	}
	if p, wild := strings.CutSuffix(pattern, "*"); wild {
		return strings.HasPrefix(id, p)
	}
	return pattern == id
}

// containmentHold is step 8's part of a HOLD_WRITES control (D21, D44): the
// write waits for one approval by a person holding incident.respond who is
// independent of the run's people, the agent's owners and the grant's
// issuers (apdomain.KindContainment).
func (s *state) containmentHold() {
	if len(s.held) == 0 {
		return
	}
	c := s.held[0]
	s.cl.add(StepRequirements, adomain.RequireApproval, ReasonContainedWrites,
		"containment control "+c.ID.String()+" holds writes on its "+c.ScopeType+": approval by an independent responder is required", "containment")
	s.ev.Requirements = append(s.ev.Requirements, apdomain.Input{
		Kind: apdomain.KindContainment, Count: 1, Independent: true,
		Source: apdomain.Source{Level: "containment", Reason: ReasonContainedWrites},
	})
}
