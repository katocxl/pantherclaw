// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Change is an authority reduction to preview (F259): grants revoked (with
// every grant delegated from them), agents suspended, connections
// quarantined, credentials revoked. Nothing here is applied: the preview
// recomputes reach on changed inputs.
type Change struct {
	RevokeGrants          []ids.UUID
	SuspendAgents         []ids.UUID
	QuarantineConnections []ids.UUID
	RevokeCredentials     []ids.UUID // connections whose active credential is revoked
	// Restrictions are containment controls (D21) on the effective view.
	Restrictions []Restriction
	// Descendants maps a grant to the grants delegated from it.
	Descendants map[ids.UUID][]ids.UUID
}

// Empty reports a change that changes nothing.
func (c Change) Empty() bool {
	return len(c.RevokeGrants) == 0 && len(c.SuspendAgents) == 0 && len(c.QuarantineConnections) == 0 &&
		len(c.RevokeCredentials) == 0 && len(c.Restrictions) == 0
}

// Apply returns in with the change made. A quarantined connection still
// reaches what a credential or route reaches outside it; only decisions
// through it stop, which Compute shows as CONDITIONAL. A suspended agent
// loses its grants' reach but keeps what it holds itself.
func (c Change) Apply(in Inputs) Inputs {
	out := in
	out.Restrictions = append(slices.Clone(in.Restrictions), c.Restrictions...)
	revoked := map[ids.UUID]bool{}
	for _, g := range c.RevokeGrants {
		revoked[g] = true
		for _, d := range c.Descendants[g] {
			revoked[d] = true
		}
	}
	out.Grants = slices.DeleteFunc(slices.Clone(in.Grants), func(g Grant) bool {
		return revoked[g.ID] || slices.Contains(c.SuspendAgents, g.Agent)
	})
	out.Connections = make([]Connection, len(in.Connections))
	for i, conn := range in.Connections {
		if slices.Contains(c.QuarantineConnections, conn.ID) && conn.State == "ACTIVE" {
			conn.State = "QUARANTINED"
		}
		if slices.Contains(c.RevokeCredentials, conn.ID) {
			conn.Credential = nil
		}
		out.Connections[i] = conn
	}
	return out
}

// Diff is reach before and after a change (F259).
type Diff struct {
	// Before and After count current rights per view.
	Before map[View]int
	After  map[View]int
	// Removed are current rights the change takes away; Weakened are those
	// that stay but become less usable; Remaining are current rights in the
	// change's scope it does not reach (another grant, a credential, a
	// route), so containment is not mistaken for closure (D31).
	Removed   []Right
	Weakened  []Right
	Remaining []Right
	// Disruption is the expected cost: recently observed work whose
	// effective right the change removes.
	Disruption []Right
	// BeforeRights and AfterRights are the two computations.
	BeforeRights, AfterRights []Right
}

// Preview computes before and after for a change.
func Preview(in Inputs, c Change) Diff {
	before := Compute(in).Rights
	after := Compute(c.Apply(in)).Rights
	return Compare(before, after, c)
}

// Compare diffs two right sets; scope decides which remaining rights the
// change was aimed at.
func Compare(before, after []Right, c Change) Diff {
	d := Diff{Before: counts(before), After: counts(after), BeforeRights: before, AfterRights: after}
	now := map[string]Right{}
	for _, r := range after {
		now[r.Key()] = r
	}
	lost := map[string]bool{}
	for _, r := range before {
		if !r.Label.Current() || r.View == Observed {
			continue
		}
		a, ok := now[r.Key()]
		switch {
		case !ok || !a.Label.Current():
			d.Removed = append(d.Removed, r)
			if r.View == Effective {
				lost[r.PathKey()] = true
			}
		case a.Label.Rank() > r.Label.Rank():
			d.Weakened = append(d.Weakened, a)
		case c.inScope(a) || (r.Grant != nil && c.revokes(*r.Grant)):
			d.Remaining = append(d.Remaining, a)
		}
	}
	for _, r := range before {
		if r.View == Observed && r.Label.Current() && lost[r.PathKey()] {
			d.Disruption = append(d.Disruption, r)
		}
	}
	return d
}

// revokes reports whether the change revokes grant, directly or as a
// descendant.
func (c Change) revokes(grant ids.UUID) bool {
	for _, g := range c.RevokeGrants {
		if g == grant || slices.Contains(c.Descendants[g], grant) {
			return true
		}
	}
	return false
}

// inScope reports whether a right belongs to what the change targets.
func (c Change) inScope(r Right) bool {
	for _, x := range c.Restrictions {
		if (x.Agent != nil && r.Agent != nil && *x.Agent == *r.Agent) || (x.Connection != nil && r.Connection != nil && *x.Connection == *r.Connection) {
			return true
		}
	}
	if r.Agent != nil && slices.Contains(c.SuspendAgents, *r.Agent) {
		return true
	}
	if r.Connection != nil && (slices.Contains(c.QuarantineConnections, *r.Connection) ||
		slices.Contains(c.RevokeCredentials, *r.Connection)) {
		return true
	}
	return false
}

func counts(rights []Right) map[View]int {
	out := map[View]int{Observed: 0, Effective: 0, Credential: 0}
	for _, r := range rights {
		if r.Label.Current() {
			out[r.View]++
		}
	}
	return out
}
