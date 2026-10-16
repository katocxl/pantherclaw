// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// IssueContext is what issuance checks need besides the grant itself.
type IssueContext struct {
	// Now is the issuance time.
	Now time.Time
	// Envelopes are the active envelopes that apply to the grant: the
	// org's, the agent's business unit's and team's, the environment's and
	// the principal's.
	Envelopes []Envelope
	// Lookup returns the org's active definition of an operation, or nil.
	Lookup func(op string) *defs.Definition
	// Parent is the parent grant of a delegation, nil for a root grant.
	// ActiveChildren and TotalChildren count its existing children.
	Parent         *Grant
	ActiveChildren int
	TotalChildren  int
	// Ceiling is the automation ceiling an automation-issued root grant is
	// issued under (G0 M11 part 2 D9, HR-271): a service-account grantor
	// is accepted only with one. The ceiling's bounds are passed as one
	// more envelope.
	Ceiling ids.UUID
}

// ValidateIssue checks a new grant or a new revision: its own shape, every
// applicable envelope (HR-045), the lifetime and delegation caps (decision
// 5), and for a delegated grant its parent (HR-047). A delegated grant must
// already carry its inherited bounds (Bounds.Inherit), so the check is
// strict. Fan-out is checked here and again by the repository while the
// parent's row is locked.
func (g Grant) ValidateIssue(ic IssueContext) error {
	if err := g.validate(ic.Lookup); err != nil {
		return err
	}
	if !g.ExpiresAt.After(ic.Now) {
		return invalid("grant: expires_at is in the past")
	}
	caps := EffectiveCaps(ic.Envelopes)
	for _, e := range ic.Envelopes {
		if v := g.Bounds.Inherit(e.Bounds).Within(e.Bounds); v != nil {
			return outside("the %s guardrail %q (revision %d) does not allow it: %s", e.Scope, e.Name, e.Revision, v)
		}
		if g.MinAttestation < e.MinAttestation {
			return outside("the %s guardrail %q requires attestation level %d or higher", e.Scope, e.Name, e.MinAttestation)
		}
	}
	if ic.Parent == nil {
		return g.validateRoot(ic, caps)
	}
	return g.validateChild(ic, caps)
}

// MaxAutomationLifetime caps an automation-issued grant (F1).
const MaxAutomationLifetime = 24 * time.Hour

func (g Grant) validateRoot(ic IssueContext, caps Caps) error {
	now := ic.Now
	automation := g.Grantor.Kind == PrincipalServiceAccount && !ic.Ceiling.IsZero()
	switch {
	case !g.Parent.IsZero() || g.Depth != 0:
		return invalid("grant: a root grant has no parent and depth 0")
	case g.Grantor.Kind != PrincipalUser && !automation:
		// Workloads never issue grants (HR-161); service accounts do not
		// either, except an automation's identity under its ceiling (G0
		// M11 part 2 D9, amending G0 M4 decision 7).
		return outside("only people issue grants (HR-161)")
	case automation && g.ExpiresAt.Sub(now) > MaxAutomationLifetime:
		return outside("an automation's grant lasts at most %s", MaxAutomationLifetime)
	case g.ExpiresAt.Sub(now) > caps.MaxRootLifetime:
		return outside("a grant may last at most %s here", caps.MaxRootLifetime)
	case g.Delegation.Depth > caps.MaxDepth:
		return outside("delegation depth %d is over the cap %d", g.Delegation.Depth, caps.MaxDepth)
	case g.Delegation.MaxChildren > caps.MaxChildren:
		return outside("max_children %d is over the cap %d", g.Delegation.MaxChildren, caps.MaxChildren)
	}
	return nil
}

func (g Grant) validateChild(ic IssueContext, caps Caps) error {
	p := *ic.Parent
	if code, ok := p.Usable(ic.Now); !ok {
		return outside("the parent grant cannot be used (%s)", code)
	}
	switch {
	case g.Parent != p.ID || g.Depth != p.Depth+1:
		return invalid("grant: a delegated grant names its parent and sits one level below it")
	case g.Org != p.Org:
		return invalid("grant: parent in another org")
	case p.Delegation.Depth < 1:
		return outside("the parent grant does not allow delegation")
	case g.Depth > caps.MaxDepth:
		return outside("delegation depth %d is over the cap %d", g.Depth, caps.MaxDepth)
	case g.Delegation.Depth > p.Delegation.Depth-1:
		return outside("a child may delegate at most %d further levels", p.Delegation.Depth-1)
	case g.Delegation.MaxChildren > min(p.Delegation.MaxChildren, caps.MaxChildren):
		return outside("a child may have at most %d children", min(p.Delegation.MaxChildren, caps.MaxChildren))
	case ic.ActiveChildren >= min(p.Delegation.MaxChildren, caps.MaxChildren):
		return outside("the parent grant already has %d active children", ic.ActiveChildren)
	case ic.TotalChildren >= MaxChildrenTotal:
		return outside("the parent grant has delegated %d times, the most a grant may", ic.TotalChildren)
	case g.Principal != p.Principal:
		return outside("a delegated grant acts for the same principal as its parent")
	case g.EnvironmentID != p.EnvironmentID:
		return outside("a delegated grant stays in its parent's environment")
	case g.NotBefore.Before(p.NotBefore) || g.ExpiresAt.After(p.ExpiresAt):
		return outside("a delegated grant cannot outlive its parent (expires %s)", p.ExpiresAt.UTC().Format(time.RFC3339))
	case g.ExpiresAt.Sub(ic.Now) > MaxDelegatedLifetime:
		return outside("a delegated grant lasts at most %s", MaxDelegatedLifetime)
	case g.MinAttestation < p.MinAttestation:
		return outside("a delegated grant cannot lower the attestation minimum %d", p.MinAttestation)
	}
	if v := g.Bounds.Within(p.Bounds); v != nil {
		return outside("wider than the parent grant: %s", v)
	}
	return nil
}

// Revision describes how a new revision of a grant differs from the
// current one.
type Revision struct {
	// Widens is set when the new revision allows anything the current one
	// does not. It is audited and checked like an issuance.
	Widens bool
	Detail string
}

// CompareRevision checks that next is a valid successor of cur (same agent,
// principal, environment and lineage) and reports whether it widens.
func CompareRevision(cur, next Grant) (Revision, error) {
	switch {
	case next.ID != cur.ID || next.Org != cur.Org || next.Revision != cur.Revision+1:
		return Revision{}, invalid("grant: a revision keeps the id and increments the revision")
	case next.AgentID != cur.AgentID || next.InstanceID != cur.InstanceID || next.Principal != cur.Principal ||
		next.EnvironmentID != cur.EnvironmentID || next.Parent != cur.Parent || next.Depth != cur.Depth:
		return Revision{}, invalid("grant: a revision cannot change the agent, principal, environment or lineage; issue a new grant")
	case cur.State != StateActive:
		return Revision{}, outside("a revoked grant cannot be revised")
	}
	if v := next.Bounds.Within(cur.Bounds); v != nil {
		return Revision{Widens: true, Detail: "bounds: " + v.Error()}, nil
	}
	for _, r := range cur.Requirements {
		if !containsRequirement(next.Requirements, r) {
			return Revision{Widens: true, Detail: "requirement " + r.Reason + " is removed or changed"}, nil
		}
	}
	if !limitsKept(cur.Limits, next.Limits) {
		return Revision{Widens: true, Detail: "a budget or counter is removed or changed"}, nil
	}
	switch {
	case next.ExpiresAt.After(cur.ExpiresAt) || next.NotBefore.Before(cur.NotBefore):
		return Revision{Widens: true, Detail: "the validity window is extended"}, nil
	case next.Delegation.Depth > cur.Delegation.Depth || next.Delegation.MaxChildren > cur.Delegation.MaxChildren:
		return Revision{Widens: true, Detail: "delegation is widened"}, nil
	case next.MinAttestation < cur.MinAttestation:
		return Revision{Widens: true, Detail: "the attestation minimum is lowered"}, nil
	}
	return Revision{Detail: "narrows or keeps every limit"}, nil
}
