// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// TestHR791_AFinalStepStillReachesFlaggedDeciders: dropping every flagged
// decider would leave a step untold, so the final step keeps them. The
// reach is the same people; nothing is approved.
// Covers: HR-791
func TestHR791_AFinalStepStillReachesFlaggedDeciders(t *testing.T) {
	reached := []wdomain.Candidate{{User: ids.NewV7(), Rank: 1}, {User: ids.NewV7(), Rank: 1}}
	got, err := fatigueLast(context.Background(), nil, ids.New[ids.Org](), reached, true)
	if err != nil || len(got) != len(reached) || got[0].User != reached[0].User {
		t.Fatalf("final step: %+v %v", got, err)
	}
	empty, err := fatigueLast(context.Background(), nil, ids.New[ids.Org](), nil, false)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty step: %+v %v", empty, err)
	}
}
