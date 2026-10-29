// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/suggestions/domain"
)

// TestDraftOperationsNeverForbidLess: a suggestion's draft forbids the
// proposed operations plus every one the published rule for the same agent
// already forbids, so drafting never loosens what is published; another
// agent's rule is left alone.
//
// Covers: F185
func TestDraftOperationsNeverForbidLess(t *testing.T) {
	agent, other := ids.NewV7(), ids.NewV7()
	proposed := Proposed(agent, []string{"stripe.refund.create"})
	if len(proposed) != 1 || proposed[0].Kind != pdomain.Forbid || proposed[0].ID != securitysteps.RestrictionRuleID(agent) {
		t.Fatalf("proposed: %+v", proposed)
	}
	if got := DraftOperations(nil, agent, proposed); !slices.Equal(got, []string{"stripe.refund.create"}) {
		t.Fatalf("no base: %v", got)
	}
	base := &pdomain.Bundle{ID: "p", Version: 2, Rules: []pdomain.Rule{
		{ID: securitysteps.RestrictionRuleID(agent), Kind: pdomain.Forbid, Operations: []string{"github.pull.merge", "stripe.refund.create"}},
		{ID: securitysteps.RestrictionRuleID(other), Kind: pdomain.Forbid, Operations: []string{"slack.message.post"}},
	}}
	got := DraftOperations(base, agent, proposed)
	if !slices.Equal(got, []string{"github.pull.merge", "stripe.refund.create"}) {
		t.Fatalf("with base: %v", got)
	}
	draft := securitysteps.RestrictionDraft(base, map[ids.UUID][]string{agent: got}, domain.WindowDays)
	for _, r := range base.Rules {
		i := slices.IndexFunc(draft.Rules, func(x pdomain.Rule) bool { return x.ID == r.ID })
		if i < 0 {
			t.Fatalf("draft lost rule %s", r.ID)
		}
		for _, op := range r.Operations {
			if !slices.Contains(draft.Rules[i].Operations, op) {
				t.Fatalf("draft rule %s no longer forbids %s", r.ID, op)
			}
		}
	}
}

// TestDraftKeepsThePublishedRuleAndOnlyAddsOperations: when a person has
// widened the published restriction rule for the agent (its When covers
// more agents, its Reason and Summary are theirs), the draft keeps that
// rule as published and only adds the proposed operations, so it never
// forbids less; the published bundle is not changed; without a published
// rule the draft adds RestrictionDraft's.
//
// Covers: F185
func TestDraftKeepsThePublishedRuleAndOnlyAddsOperations(t *testing.T) {
	agent, other := ids.NewV7(), ids.NewV7()
	proposed := Proposed(agent, []string{"stripe.refund.create"})
	widened := pdomain.Rule{
		ID: securitysteps.RestrictionRuleID(agent), Kind: pdomain.Forbid, Summary: "Forbid both agents merges",
		Operations: []string{"github.pull.merge"},
		When:       `run.agent_id in ["` + agent.String() + `", "` + other.String() + `"]`, Reason: "FROZEN_BY_SECURITY",
	}
	base := &pdomain.Bundle{ID: "p", Version: 3, Rules: []pdomain.Rule{
		widened,
		{ID: "other", Kind: pdomain.Annotate, Operations: []string{"slack.message.post"}, When: "true"},
	}}
	draft := DraftBundle(base, agent, proposed)
	if len(draft.Rules) != 2 || draft.ID != "p" || draft.Version != 3 {
		t.Fatalf("draft: %+v", draft)
	}
	got := draft.Rules[0]
	if got.When != widened.When || got.Reason != widened.Reason || got.Summary != widened.Summary || got.Kind != pdomain.Forbid {
		t.Fatalf("draft rewrote the published rule: %+v", got)
	}
	if !slices.Equal(got.Operations, []string{"github.pull.merge", "stripe.refund.create"}) {
		t.Fatalf("operations: %v", got.Operations)
	}
	if !slices.Equal(base.Rules[0].Operations, []string{"github.pull.merge"}) {
		t.Fatalf("the published bundle changed: %v", base.Rules[0].Operations)
	}
	if draft.Rules[1].ID != "other" || draft.Rules[1].When != "true" {
		t.Fatalf("another rule changed: %+v", draft.Rules[1])
	}

	fresh := DraftBundle(nil, agent, proposed)
	if len(fresh.Rules) != 1 || fresh.Rules[0].When != proposed[0].When || !slices.Equal(fresh.Rules[0].Operations, proposed[0].Operations) {
		t.Fatalf("no base: %+v", fresh.Rules)
	}
}
