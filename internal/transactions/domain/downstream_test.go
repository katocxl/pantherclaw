// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// TestHR451_DownstreamIsConfirmedOnlyByEveryConsequencesOwnEvidence (G0
// M17 D102, D131): an action's downstream state is CONFIRMED only when
// every consequence opened for it, and every consequence of those, was
// confirmed by its own evidence. Precedence over the whole subtree is
// UNCONFIRMED > NOT_VERIFIABLE > PENDING > CONFIRMED: a consequence that
// could not be opened caps the action at NOT_VERIFIABLE whatever the
// opened ones show (the mixed case), and a negative outcome still makes it
// UNCONFIRMED.
//
// Covers: F414
func TestHR451_DownstreamIsConfirmedOnlyByEveryConsequencesOwnEvidence(t *testing.T) {
	ok := domain.Consequence{Effect: domain.Confirmed}
	pending := domain.Consequence{Effect: domain.PropagationPending}
	opened := domain.Consequence{}
	asked := domain.Consequence{Effect: domain.PropagationPending, Questioned: true}
	for _, c := range []struct {
		name   string
		cs     []domain.Consequence
		capped bool
		want   domain.DownstreamState
	}{
		{"none opened", nil, false, domain.DownstreamPending},
		{"just opened", []domain.Consequence{opened}, false, domain.DownstreamPending},
		{"one of two confirmed", []domain.Consequence{ok, pending}, false, domain.DownstreamPending},
		{"every one confirmed", []domain.Consequence{ok, ok}, false, domain.DownstreamConfirmed},
		{"a person was asked", []domain.Consequence{ok, asked}, false, domain.DownstreamUnconfirmed},
		{"released as not occurred, though confirmed later", []domain.Consequence{{Effect: domain.Confirmed, Questioned: true}}, false,
			domain.DownstreamUnconfirmed},
		{"no effect found", []domain.Consequence{ok, {Effect: domain.NoneConfirmed}}, false, domain.DownstreamUnconfirmed},
		{"unknown at the deadline", []domain.Consequence{{Effect: domain.Unknown}}, false, domain.DownstreamUnconfirmed},
		{"conflicting", []domain.Consequence{{Effect: domain.Conflicting}}, false, domain.DownstreamUnconfirmed},
		{"partial", []domain.Consequence{{Effect: domain.Partial}}, false, domain.DownstreamUnconfirmed},
		{"compensated", []domain.Consequence{{Effect: domain.Compensated}}, false, domain.DownstreamUnconfirmed},
		{"unverifiable", []domain.Consequence{{Effect: domain.Unverifiable}}, false, domain.DownstreamUnconfirmed},
		// Mixed: one consequence could not be opened, the opened ones confirm.
		{"mixed, opened ones confirmed", []domain.Consequence{ok, ok}, true, domain.DownstreamNotVerifiable},
		{"mixed, opened one pending", []domain.Consequence{pending}, true, domain.DownstreamNotVerifiable},
		{"mixed, nothing opened", nil, true, domain.DownstreamNotVerifiable},
		{"mixed, a negative outcome", []domain.Consequence{ok, asked}, true, domain.DownstreamUnconfirmed},
		// The subtree: a consequence's own consequences count.
		{"child confirmed, its subtree pending", []domain.Consequence{{Effect: domain.Confirmed, Downstream: domain.DownstreamPending}}, false,
			domain.DownstreamPending},
		{"child confirmed, its subtree confirmed", []domain.Consequence{{Effect: domain.Confirmed, Downstream: domain.DownstreamConfirmed}}, false,
			domain.DownstreamConfirmed},
		{"child confirmed, its subtree not verifiable", []domain.Consequence{ok, {Effect: domain.Confirmed, Downstream: domain.DownstreamNotVerifiable}},
			false, domain.DownstreamNotVerifiable},
		{"child confirmed, its subtree unconfirmed", []domain.Consequence{{Effect: domain.Confirmed, Downstream: domain.DownstreamUnconfirmed}}, true,
			domain.DownstreamUnconfirmed},
	} {
		if got := domain.Downstream(c.cs, c.capped); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
