// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
)

// TestF021_ProtectedOnlyWhileEveryScopeIsEnforced: an agent is PROTECTED
// only when every scope that counts is ENFORCED, PARTIALLY_PROTECTED for a
// mix and OBSERVED when none is; a whole-scope exclusion does not count.
func TestF021_ProtectedOnlyWhileEveryScopeIsEnforced(t *testing.T) {
	e, p, o := domain.Enforced, domain.Partial, domain.ObserveOnly
	for _, c := range []struct {
		states   []domain.State
		excluded []bool
		want     adomain.State
	}{
		{nil, nil, adomain.StateObserved},
		{[]domain.State{e}, []bool{false}, adomain.StateProtected},
		{[]domain.State{e, e}, []bool{false, false}, adomain.StateProtected},
		{[]domain.State{e, p}, []bool{false, false}, adomain.StatePartiallyProtected},
		{[]domain.State{p, o}, []bool{false, false}, adomain.StateObserved},
		{[]domain.State{e, p}, []bool{false, true}, adomain.StateProtected},
		{[]domain.State{e}, []bool{true}, adomain.StateObserved},
	} {
		if got := app.Protection(c.states, c.excluded); got != c.want {
			t.Errorf("%v excluded %v: %s, want %s", c.states, c.excluded, got, c.want)
		}
	}
}
