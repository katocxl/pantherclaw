// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestCustomerStepKindsAreTheLiveKinds: a customer scenario uses exactly the
// step kinds the live driver runs, and no harness kind (G0 M17 D126).
// Covers: PN-009.6
func TestCustomerStepKindsAreTheLiveKinds(t *testing.T) {
	d := live.New(live.Config{})
	for _, k := range domain.StepKinds {
		allowed := false
		for _, c := range domain.CustomerStepKinds {
			allowed = allowed || c == k
		}
		if allowed != d.Supports(k) {
			t.Errorf("%s: customer kind %v, live driver supports %v", k, allowed, d.Supports(k))
		}
	}
}

// harnessCapabilities are the capabilities only the harness provides, each
// for a step kind the live driver lacks or a stack a live range does not
// run: sandbox (sandbox.probe), second_org (server.read), browser
// (browser.call), the simulator swaps and slack.interaction_post
// (sim.mutate), billing (a stack with hosted plans), aws.ecs.deploy (on a
// live range, a real deploy).
var harnessCapabilities = []string{
	"sandbox", "second_org", "browser", "stripe.key_swap", "pg.role_swap", "a2a.card_swap", "slack.interaction_post", "billing", "aws.ecs.deploy",
}

// TestCustomerCapabilitiesAreWhatALiveRangeProvides: every capability is
// either one a customer scenario may require or a harness one, never both;
// every capability a library scenario the live driver runs end to end
// requires is open to customer scenarios; and the simulators the CLI's
// --provides names are too (G0 M17 D126).
// Covers: PN-009.6
func TestCustomerCapabilitiesAreWhatALiveRangeProvides(t *testing.T) {
	for _, c := range domain.KnownCapabilities() {
		customer, harness := slices.Contains(domain.CustomerCapabilities, c), slices.Contains(harnessCapabilities, c)
		if customer == harness {
			t.Errorf("%s: customer %v, harness %v: classify it exactly once", c, customer, harness)
		}
	}
	for _, c := range domain.CustomerCapabilities {
		if !slices.Contains(domain.KnownCapabilities(), c) {
			t.Errorf("%s is not a capability", c)
		}
	}
	set, err := app.LoadDir("../../../../redteam/scenarios")
	if err != nil {
		t.Fatal(err)
	}
	d := live.New(live.Config{})
	for _, l := range set {
		runs := !l.Scenario.HarnessOnly
		for _, st := range l.Scenario.Steps {
			runs = runs && d.Supports(st.Do)
		}
		for _, r := range l.Scenario.Requires {
			if runs && !slices.Contains(domain.CustomerCapabilities, r) {
				t.Errorf("%s runs on the live driver and requires %s, which customer scenarios cannot", l.Scenario.ID, r)
			}
		}
	}
	for _, c := range []string{"github", "payments", "mcp", "person"} {
		if !slices.Contains(domain.CustomerCapabilities, c) {
			t.Errorf("%s is provided by a live range but closed to customer scenarios", c)
		}
	}
}
