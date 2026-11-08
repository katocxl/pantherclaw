// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
)

var allStates = []domain.State{
	domain.StateDiscovered, domain.StateClaimed, domain.StateVerified, domain.StateObserved,
	domain.StatePartiallyProtected, domain.StateProtected, domain.StateSuspended, domain.StateRetired,
}

// TestAgentLifecycleTable checks every pair of states against the intended
// table (F020), so an accidental transition cannot slip in.
func TestAgentLifecycleTable(t *testing.T) {
	type pair struct{ from, to domain.State }
	want := map[pair]bool{}
	allow := func(from domain.State, tos ...domain.State) {
		for _, to := range tos {
			want[pair{from, to}] = true
		}
	}
	allow(domain.StateDiscovered, domain.StateClaimed, domain.StateSuspended, domain.StateRetired)
	allow(domain.StateClaimed, domain.StateVerified, domain.StateSuspended, domain.StateRetired)
	allow(domain.StateVerified, domain.StateObserved, domain.StateSuspended, domain.StateRetired)
	allow(domain.StateObserved, domain.StatePartiallyProtected, domain.StateProtected, domain.StateSuspended, domain.StateRetired)
	allow(domain.StatePartiallyProtected, domain.StateObserved, domain.StateProtected, domain.StateSuspended, domain.StateRetired)
	allow(domain.StateProtected, domain.StateObserved, domain.StatePartiallyProtected, domain.StateSuspended, domain.StateRetired)
	allow(domain.StateSuspended, domain.StateRetired)
	for _, from := range allStates {
		for _, to := range allStates {
			err := domain.Lifecycle.Check(from, to)
			if got := err == nil; got != want[pair{from, to}] {
				t.Errorf("%s → %s allowed = %v", from, to, got)
			}
			if err != nil && !errors.Is(err, statemachine.ErrIllegalTransition) {
				t.Errorf("%s → %s: %v", from, to, err)
			}
		}
	}
	if !domain.Lifecycle.Terminal(domain.StateRetired) {
		t.Error("RETIRED must be terminal (F023)")
	}
	if !slices.Equal(domain.Lifecycle.Next(domain.StateSuspended), []domain.State{domain.StateRetired}) {
		t.Error("a suspended agent may only be retired until M5 restoration entries exist (F563)")
	}
}

// TestHR148_DiscoveredAgentsHoldNoAuthority: only claimed, non-contained
// agents are usable; a discovered agent has no owner.
func TestHR148_DiscoveredAgentsHoldNoAuthority(t *testing.T) {
	for _, s := range allStates {
		usable := s.Usable()
		want := s != domain.StateDiscovered && s != domain.StateSuspended && s != domain.StateRetired
		if usable != want {
			t.Errorf("%s usable = %v", s, usable)
		}
		if s.NextAction() == "" {
			t.Errorf("%s has no next action (F020)", s)
		}
	}
	if domain.StateDiscovered.Claimed("") || domain.StateSuspended.Claimed(domain.StateDiscovered) {
		t.Error("a discovered agent, or one suspended while discovered, has no owner")
	}
	if !domain.StateSuspended.Claimed(domain.StateVerified) {
		t.Error("an agent suspended after its claim keeps its owner")
	}
}

// TestHR092_DesktopAgentsCappedAtL1: desktop instances never exceed L1,
// whatever attestation they present (ADR-0013). Other contexts reach L3
// with an infrastructure attestation (G0 M35 D1030).
func TestHR092_DesktopAgentsCappedAtL1(t *testing.T) {
	for c, want := range map[domain.ExecutionContext]int{
		domain.ContextDesktop: 1, domain.ContextCI: 3, domain.ContextKubernetes: 3, domain.ContextService: 3,
	} {
		if got := c.MaxAttestationLevel(); got != want {
			t.Errorf("%s: max level %d, want %d", c, got, want)
		}
	}
	if domain.ExecutionContext("laptop").Valid() {
		t.Error("unknown execution context accepted")
	}
}

func details() domain.Details {
	return domain.Details{
		Name: "Claude Code, engineering", Purpose: "Writes and reviews code.",
		TeamID: ids.NewV7(), EnvironmentID: ids.NewV7(), OwnerUserID: ids.NewV7(),
		Context: domain.ContextCI,
	}
}

func TestDetailsValidation(t *testing.T) {
	if err := details().Validate(); err != nil {
		t.Fatalf("valid details: %v", err)
	}
	bad := map[string]func(*domain.Details){
		"empty name":           func(d *domain.Details) { d.Name = "  " },
		"long name":            func(d *domain.Details) { d.Name = strings.Repeat("a", domain.MaxNameLen+1) },
		"bidi in name":         func(d *domain.Details) { d.Name = "coder\u202egnp.exe" },
		"control in purpose":   func(d *domain.Details) { d.Purpose = "a\x00b" },
		"long purpose":         func(d *domain.Details) { d.Purpose = strings.Repeat("a", domain.MaxPurposeLen+1) },
		"no team":              func(d *domain.Details) { d.TeamID = ids.UUID{} },
		"no environment":       func(d *domain.Details) { d.EnvironmentID = ids.UUID{} },
		"no owner":             func(d *domain.Details) { d.OwnerUserID = ids.UUID{} },
		"owner is also backup": func(d *domain.Details) { d.BackupOwnerUserID = d.OwnerUserID },
		"no context":           func(d *domain.Details) { d.Context = "" },
	}
	for name, mutate := range bad {
		d := details()
		mutate(&d)
		if err := d.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if err := domain.ValidateReason(""); !errors.Is(err, domain.ErrInvalid) {
		t.Error("an empty reason was accepted")
	}
}

// TestHR147_NamesBindNothing: a display name is a free label; two agents may
// share one, and nothing in the domain keys anything on it.
func TestHR147_NamesBindNothing(t *testing.T) {
	a, b := details(), details()
	b.Name = a.Name
	if a.Validate() != nil || b.Validate() != nil {
		t.Fatal("two agents with one name must both be valid")
	}
	if a.TeamID == b.TeamID || a.OwnerUserID == b.OwnerUserID {
		t.Fatal("fixture ids collide")
	}
}

func TestActivityStatus(t *testing.T) {
	for _, tc := range []struct {
		admitted, observed bool
		want               domain.ActivityStatus
	}{
		{false, false, domain.ActivityNoInstances},
		{true, false, domain.ActivityVerifiedNoActions},
		{true, true, domain.ActivityActive},
	} {
		if got := domain.Activity(tc.admitted, tc.observed); got != tc.want {
			t.Errorf("Activity(%v, %v) = %s", tc.admitted, tc.observed, got)
		}
	}
}

func TestChangeValidation(t *testing.T) {
	ok := domain.Change{
		Kind: domain.ChangeClaimed, Actor: domain.UserActor(ids.NewV7()), Reason: "found in CI",
		Details: map[string]string{"discovery_id": ids.NewV7().String()},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid change: %v", err)
	}
	for name, c := range map[string]domain.Change{
		"bad kind":        {Kind: "Agent Claimed", Actor: domain.System},
		"no actor":        {Kind: domain.ChangeClaimed},
		"bidi reason":     {Kind: domain.ChangeClaimed, Actor: domain.System, Reason: "x\u2066y"},
		"bad detail key":  {Kind: domain.ChangeClaimed, Actor: domain.System, Details: map[string]string{"Key": "v"}},
		"long detail":     {Kind: domain.ChangeClaimed, Actor: domain.System, Details: map[string]string{"note": strings.Repeat("v", 257)}},
		"control in note": {Kind: domain.ChangeClaimed, Actor: domain.System, Details: map[string]string{"note": "a\rb"}},
	} {
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
