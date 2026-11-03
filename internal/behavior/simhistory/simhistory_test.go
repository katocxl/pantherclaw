// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simhistory_test

import (
	"slices"
	"testing"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/behavior/simhistory"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

func spec(seed uint64) simhistory.Spec {
	return simhistory.Spec{
		Agent: ids.NewV7(), Connection: ids.NewV7(), DestClass: "INTERNAL",
		Operations: []string{"repo.read", "repo.write"}, Days: 14, RunsPerDay: 3, Hour: 9,
		End: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC), SpendOperation: "payments.refund",
		Amount: money.MustParse("12.50"), Currency: "USD", Seed: seed,
	}
}

// TestHR642_SimulatedHistoryIsRepeatableAndEnoughForAProfile: the same seed
// gives the same history, another seed another, and a fortnight of it is
// enough for a COLLECTED profile whose window holds every action. It is
// made-up history, built only into a SIMULATED profile. Covers: F931
func TestHR642_SimulatedHistoryIsRepeatableAndEnoughForAProfile(t *testing.T) {
	s := spec(7)
	a, b := simhistory.Actions(s), simhistory.Actions(s)
	if !slices.EqualFunc(a, b, func(x, y bdomain.Action) bool { return x.ID == y.ID && x.Run == y.Run && x.At.Equal(y.At) }) {
		t.Fatal("the same seed gave another history")
	}
	other := spec(8)
	other.Agent, other.Connection = s.Agent, s.Connection
	if c := simhistory.Actions(other); c[0].ID == a[0].ID {
		t.Fatal("another seed gave the same ids")
	}
	if want := s.Days * (s.RunsPerDay*len(s.Operations) + 1); len(a) != want {
		t.Fatalf("actions = %d, want %d", len(a), want)
	}
	start := s.End.Add(-bdomain.Window)
	for _, x := range a {
		if x.Agent != s.Agent || x.At.Before(start) || !x.At.Before(s.End) {
			t.Fatalf("action outside the agent or window: %+v", x)
		}
	}
	p := bdomain.Build(s.Agent, bdomain.OriginSimulated, a, start, s.End, false)
	if p.State != bdomain.StateCollected || p.Origin != bdomain.OriginSimulated || p.ActiveDays != s.Days {
		t.Fatalf("profile = %s %s %d days", p.State, p.Origin, p.ActiveDays)
	}
	if len(p.Body.Spend) != 1 || p.Body.Spend[0].Currency != "USD" || p.Body.Spend[0].MaxDaily != "12.5" {
		t.Fatalf("spend = %+v", p.Body.Spend)
	}
	if simhistory.Generator == "" {
		t.Fatal("rows carry no generator label")
	}
}
