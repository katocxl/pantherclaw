// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR644_EachAgentGetsAShareOfTheAlerts: one noisy agent raises at most
// MaxSignalsPerAgent alerts in a run, the others still get theirs, and the
// run never raises more than MaxSignals (D548). Covers: F932
func TestHR644_EachAgentGetsAShareOfTheAlerts(t *testing.T) {
	noisy, quiet := ids.NewV7(), ids.NewV7()
	var ds []found
	for range 500 {
		ds = append(ds, found{Deviation: bdomain.Deviation{Action: bdomain.Action{Agent: noisy}}})
	}
	for range 3 {
		ds = append(ds, found{Deviation: bdomain.Deviation{Action: bdomain.Action{Agent: quiet}}})
	}
	count := func(fs []found) map[ids.UUID]int {
		m := map[ids.UUID]int{}
		for _, f := range fs {
			m[f.Action.Agent]++
		}
		return m
	}
	got := count(shares(ds))
	if got[noisy] != MaxSignalsPerAgent || got[quiet] != 3 {
		t.Fatalf("shares = %v", got)
	}

	var many []found
	for range 30 {
		a := ids.NewV7()
		for range MaxSignalsPerAgent {
			many = append(many, found{Deviation: bdomain.Deviation{Action: bdomain.Action{Agent: a}}})
		}
	}
	all := shares(many)
	if len(all) != MaxSignals {
		t.Fatalf("raised %d, want %d", len(all), MaxSignals)
	}
	for a, n := range count(all) {
		if n < MaxSignals/30 || n > MaxSignals/30+1 {
			t.Errorf("agent %s got %d of the shared alerts", a, n)
		}
	}
}
