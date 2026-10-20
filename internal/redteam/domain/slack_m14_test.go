// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestM14_SlackSimChangesOnlyForSlack: reaction, reply and interaction_post
// mutate the Slack simulator only (G0 M14 D91).
func TestM14_SlackSimChangesOnlyForSlack(t *testing.T) {
	for _, change := range []string{"reaction", "reply", "interaction_post"} {
		if err := parseSteps("  - {id: a, do: sim.mutate, with: {sim: slack, change: " + change + "}}\n"); err != nil {
			t.Errorf("slack %s: %v", change, err)
		}
		for _, sim := range []string{"github", "payments", "stripe"} {
			err := parseSteps("  - {id: a, do: sim.mutate, with: {sim: " + sim + ", change: " + change + "}}\n")
			if !errors.Is(err, domain.ErrInvalid) {
				t.Errorf("%s %s: %v", sim, change, err)
			}
		}
	}
}
