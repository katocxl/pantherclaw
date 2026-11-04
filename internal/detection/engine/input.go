// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// ReadsKind reports whether kind is one of the rule's inputs: its on list
// or any sequence step's (G0 M28 D716).
func ReadsKind(r *rules.Rule, kind string) bool {
	if rules.KindMatches(r.On, kind) {
		return true
	}
	if r.Sequence != nil {
		for _, s := range r.Sequence.Steps {
			if rules.KindMatches(s.On, kind) {
				return true
			}
		}
	}
	return false
}

// LastInputs returns, per rule of set that saw input in events, the newest
// occurred_at among the events of a kind it reads, whether or not it fired
// (G0 M28 D716). Reflex's own entries are never input.
func LastInputs(set []*Compiled, events []feed.Event) map[string]time.Time {
	out := map[string]time.Time{}
	for _, ev := range events {
		if reflexdomain.ReflexKind(ev.Kind) {
			continue
		}
		for _, c := range set {
			if !ReadsKind(c.Rule, ev.Kind) {
				continue
			}
			if t, ok := out[c.Rule.ID]; !ok || ev.OccurredAt.After(t) {
				out[c.Rule.ID] = ev.OccurredAt
			}
		}
	}
	return out
}

// saveInputs writes each rule's last input time: one write per rule that
// saw input, in the transaction that advances the cursor (G0 M28 D716).
func saveInputs(ctx context.Context, q *dbq.Queries, org ids.OrgID, set []*Compiled, events []feed.Event) error {
	last := LastInputs(set, events)
	ruleIDs := make([]string, 0, len(last))
	for id := range last {
		ruleIDs = append(ruleIDs, id)
	}
	slices.Sort(ruleIDs) // a fixed lock order across concurrent runs
	for _, id := range ruleIDs {
		if err := q.TouchDetectionRuleInput(ctx, org, id, last[id]); err != nil {
			return err
		}
	}
	return nil
}
