// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// Covers: F123

var (
	chanA = actionir.Destination{Kind: "external", ID: "C0A"}
	chanB = actionir.Destination{Kind: "external", ID: "C0B"}
)

func flow(classes []string, dests ...actionir.Destination) FlowAllowance {
	return FlowAllowance{Classes: classes, Destinations: dests}
}

// TestHR432_FlowsOnlyNarrowUnderDelegation: each child flow must be covered
// by one of the parent's (classes and destinations both subsets); a wider
// one is the lattice error. A parent without flows lets a child have none.
func TestHR432_FlowsOnlyNarrowUnderDelegation(t *testing.T) {
	p := rootGrant(t, refundBounds)
	p.Flows = []FlowAllowance{flow([]string{"pii"}, chanA, chanB), flow([]string{"pii", "secret"}, chanA)}
	if err := issue(p, nil); err != nil {
		t.Fatalf("parent: %v", err)
	}
	for name, flows := range map[string][]FlowAllowance{
		"none":           nil,
		"the same":       p.Flows,
		"fewer dests":    {flow([]string{"pii"}, chanB)},
		"one per parent": {flow([]string{"secret"}, chanA), flow([]string{"pii"}, chanB)},
	} {
		c := childOf(t, p, refundBounds)
		c.Flows = flows
		if err := issue(c, &p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, flows := range map[string][]FlowAllowance{
		"a class the parent lacks for that destination": {flow([]string{"secret"}, chanB)},
		"a destination the parent lacks":                {flow([]string{"pii"}, actionir.Destination{Kind: "external", ID: "C0Z"})},
		"spread across two parent flows":                {flow([]string{"pii", "secret"}, chanA, chanB)},
	} {
		c := childOf(t, p, refundBounds)
		c.Flows = flows
		if err := issue(c, &p); !errors.Is(err, ErrOutside) {
			t.Errorf("%s: %v, want ErrOutside", name, err)
		}
	}
}

// TestHR432_ANarrowedParentStopsTheChildsFlow: a flow is checked at every
// grant of the chain, so a parent's narrowing revision (no review, no
// cascade) stops the flow its delegated child still names.
func TestHR432_ANarrowedParentStopsTheChildsFlow(t *testing.T) {
	p := rootGrant(t, refundBounds)
	p.Flows = []FlowAllowance{flow([]string{"pii"}, chanA)}
	c := childOf(t, p, refundBounds)
	c.Flows = p.Flows
	if err := issue(c, &p); err != nil {
		t.Fatal(err)
	}
	pii, dests := []string{"pii"}, []actionir.Destination{chanA}
	if !(Chain{Grants: []Grant{p, c}}).FlowCovers(pii, dests) {
		t.Fatal("the chain does not cover a flow every grant names")
	}
	next := p
	next.Revision, next.Flows = 2, nil
	if r, err := CompareRevision(p, next); err != nil || r.Widens {
		t.Fatalf("removing the flow: widens %v %v", r.Widens, err)
	}
	if (Chain{Grants: []Grant{next, c}}).FlowCovers(pii, dests) {
		t.Fatal("the child's flow survives the parent's narrowing revision")
	}
	if (Chain{}).FlowCovers(pii, dests) {
		t.Fatal("a chain without grants covers a flow")
	}
}

// TestHR432_NilFlowsAllowNothing: a grant without flows covers no flow,
// and a flow never covers an action without destinations.
func TestHR432_NilFlowsAllowNothing(t *testing.T) {
	if FlowCovers(nil, []string{"pii"}, []actionir.Destination{chanA}) {
		t.Fatal("nil flows allow a flow")
	}
	f := []FlowAllowance{flow([]string{"pii"}, chanA)}
	switch {
	case !FlowCovers(f, []string{"pii"}, []actionir.Destination{chanA}):
		t.Fatal("a covering flow does not cover")
	case FlowCovers(f, []string{"pii"}, nil):
		t.Fatal("an action without destinations matched")
	case FlowCovers(f, []string{"pii", "secret"}, []actionir.Destination{chanA}):
		t.Fatal("a class outside the flow is covered")
	case FlowCovers(f, []string{"pii"}, []actionir.Destination{chanA, chanB}):
		t.Fatal("a destination outside the flow is covered")
	}
}

// TestHR432_ARevisionThatAddsAFlowWidens (D94): adding or widening a flow
// widens the revision; removing or narrowing one narrows.
func TestHR432_ARevisionThatAddsAFlowWidens(t *testing.T) {
	cur := rootGrant(t, refundBounds)
	cur.Flows = []FlowAllowance{flow([]string{"pii"}, chanA, chanB)}
	for name, c := range map[string]struct {
		flows  []FlowAllowance
		widens bool
	}{
		"added":        {append(cur.Flows, flow([]string{"secret"}, chanA)), true},
		"more classes": {[]FlowAllowance{flow([]string{"pii", "secret"}, chanA, chanB)}, true},
		"more dests":   {[]FlowAllowance{flow([]string{"pii"}, chanA, chanB, actionir.Destination{Kind: "internal", ID: "x"})}, true},
		"kept":         {cur.Flows, false},
		"fewer dests":  {[]FlowAllowance{flow([]string{"pii"}, chanA)}, false},
		"removed":      {nil, false},
	} {
		next := cur
		next.Revision, next.Flows = 2, c.flows
		r, err := CompareRevision(cur, next)
		if err != nil || r.Widens != c.widens {
			t.Errorf("%s: widens %v (%s) %v, want %v", name, r.Widens, r.Detail, err, c.widens)
		}
	}
}

// TestT197_AChildCannotClaimAWiderFlow: a delegated grant claiming a flow
// its parent does not hold is refused, also when the parent holds none.
func TestT197_AChildCannotClaimAWiderFlow(t *testing.T) {
	p := rootGrant(t, refundBounds)
	c := childOf(t, p, refundBounds)
	c.Flows = []FlowAllowance{flow([]string{"pii"}, chanA)}
	if err := issue(c, &p); !errors.Is(err, ErrOutside) {
		t.Fatalf("a parent without flows: %v", err)
	}
	p.Flows = []FlowAllowance{flow([]string{"pii"}, chanA)}
	c = childOf(t, p, refundBounds)
	c.Flows = []FlowAllowance{flow([]string{"pii", "secret"}, chanA)}
	if err := issue(c, &p); !errors.Is(err, ErrOutside) {
		t.Fatalf("a wider class: %v", err)
	}
}

// TestFlowValidation: flows are validated and decoded strictly.
func TestFlowValidation(t *testing.T) {
	for name, f := range map[string]FlowAllowance{
		"no class":          flow(nil, chanA),
		"no destination":    flow([]string{"pii"}),
		"an open class":     flow([]string{"internal"}, chanA),
		"a repeated class":  flow([]string{"pii", "pii"}, chanA),
		"an unknown kind":   flow([]string{"pii"}, actionir.Destination{Kind: "slack", ID: "C"}),
		"an empty id":       flow([]string{"pii"}, actionir.Destination{Kind: "external"}),
		"a repeated target": flow([]string{"pii"}, chanA, chanA),
	} {
		g := rootGrant(t, refundBounds)
		g.Flows = []FlowAllowance{f}
		if err := issue(g, nil); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	raw, err := EncodeFlows([]FlowAllowance{flow([]string{"pii"}, chanA)})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeFlows(raw); err != nil || len(got) != 1 || got[0].Destinations[0] != chanA {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if raw, _ := EncodeFlows(nil); raw != nil {
		t.Fatal("no flows are stored as a value")
	}
	if _, err := DecodeFlows([]byte(`[{"classes":["pii"],"destinations":[{"kind":"external","id":"x"}],"extra":1}]`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown member: %v", err)
	}
}
