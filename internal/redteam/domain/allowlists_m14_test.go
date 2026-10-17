// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestM14_RangeAllowLists: scenarios may require the M14 capabilities,
// mutate the M14 simulators and call through the a2a and authzen faces
// (G0 M14 D46); anything else stays refused.
func TestM14_RangeAllowLists(t *testing.T) {
	for _, c := range []string{
		"stripe.refund", "stripe.transfer", "stripe.key_swap", "pg.query", "pg.role_swap", "slack.post",
		"slack.interaction_post", "authzen.evaluate", "a2a.send", "a2a.card_swap",
	} {
		doc := header + "requires: [" + c + "]\nsteps:\n  - {id: a, do: operator.revoke_grant}\n"
		if _, err := domain.Parse([]byte(doc)); err != nil {
			t.Errorf("requires %s: %v", c, err)
		}
	}
	for _, sim := range []string{"stripe", "postgres", "slack", "a2a"} {
		if err := parseSteps("  - {id: a, do: sim.mutate, with: {sim: " + sim + ", change: fault}}\n"); err != nil {
			t.Errorf("sim %s: %v", sim, err)
		}
	}
	for _, face := range []string{"a2a", "authzen"} {
		if err := parseSteps("  - {id: a, do: agent.call, with: {face: " + face + ", connection: g, tool: t}, expect: {outcome: DENY}}\n"); err != nil {
			t.Errorf("face %s: %v", face, err)
		}
	}
	for name, doc := range map[string]string{
		"capability": header + "requires: [stripe.live]\nsteps:\n  - {id: a, do: operator.revoke_grant}\n",
		"sim":        header + "steps:\n  - {id: a, do: sim.mutate, with: {sim: mysql, change: fault}}\n",
		"face":       header + "steps:\n  - {id: a, do: agent.call, with: {face: smtp, connection: g, tool: t}, expect: {outcome: DENY}}\n",
	} {
		if _, err := domain.Parse([]byte(doc)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("unknown %s: %v", name, err)
		}
	}
}
