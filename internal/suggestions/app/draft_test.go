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
