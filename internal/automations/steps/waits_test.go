// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

// TestHR452_AWaitOnConsequencesPassesOnlyOnConfirmed (G0 M17 D103): a
// wait_effect step with consequences passes only when enough of the run's
// actions have every consequence confirmed by its own evidence. An
// unconfirmed or not verifiable consequence never passes: it keeps the
// step waiting while the run is active and then needs reconciliation;
// so does a consequence still pending at the timeout. Actions whose
// consequences are only pending keep the step waiting, even after the run
// ended, and a min that cannot be reached fails.
//
// Covers: F414
func TestHR452_AWaitOnConsequencesPassesOnlyOnConfirmed(t *testing.T) {
	type counts = dbq.RunDownstreamCountsRow
	for _, c := range []struct {
		name             string
		c                counts
		want             int
		active, timedOut bool
		state            autodomain.StepState
		reason           string
	}{
		{"confirmed", counts{Confirmed: 1}, 1, true, false, autodomain.StepDone, ""},
		{"confirmed, though another is unconfirmed", counts{Confirmed: 2, Unconfirmed: 1}, 2, false, false, autodomain.StepDone, ""},
		{"too few confirmed, run active", counts{Confirmed: 1}, 2, true, false, autodomain.StepWaiting, ""},
		{"pending after the run ended", counts{Pending: 1}, 1, false, false, autodomain.StepWaiting, ""},
		{"unconfirmed, run active", counts{Unconfirmed: 1}, 1, true, false, autodomain.StepWaiting, ""},
		{"unconfirmed after the run ended", counts{Unconfirmed: 1}, 1, false, false, autodomain.StepUnknown, engine.ReasonEffectUnknown},
		{"not verifiable at the timeout", counts{Unconfirmed: 1}, 1, true, true, autodomain.StepUnknown, engine.ReasonEffectUnknown},
		{"pending at the timeout", counts{Pending: 1}, 1, true, true, autodomain.StepUnknown, engine.ReasonEffectUnknown},
		{"unconfirmed with one short of min", counts{Confirmed: 1, Unconfirmed: 1}, 2, false, false, autodomain.StepUnknown,
			engine.ReasonEffectUnknown},
		{"nothing predicted, run ended", counts{}, 1, false, false, autodomain.StepFailed, ReasonNoEffect},
		{"nothing predicted at the timeout", counts{}, 1, true, true, autodomain.StepFailed, engine.ReasonTimeout},
	} {
		state, reason := downstreamOutcome(c.c, c.want, c.active, c.timedOut)
		if state != c.state || reason != c.reason {
			t.Errorf("%s: %s %q, want %s %q", c.name, state, reason, c.state, c.reason)
		}
		if state == autodomain.StepDone && int(c.c.Confirmed) < c.want {
			t.Errorf("%s: passed with %d confirmed of %d", c.name, c.c.Confirmed, c.want)
		}
	}
}
