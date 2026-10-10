// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

func seconds(n int32) *int32 { return &n }

// TestHR177_DeadlinesComeFromTheKindAndOnlyShorten: each kind has its
// decision-6 deadline, an org setting may only shorten it, and only access
// requests and tool reviews end at their deadline (a RECONCILIATION entry
// never resolves by itself).
func TestHR177_DeadlinesComeFromTheKindAndOnlyShorten(t *testing.T) {
	day := 24 * time.Hour
	for kind, want := range map[string]time.Duration{
		domain.KindAccessRequest: 7 * day, domain.KindToolReview: 30 * day, domain.KindRestoration: day,
		domain.KindReconciliation: 3 * day, domain.KindAdmission: 7 * day,
	} {
		if got := domain.Deadline(kind, nil); got != want {
			t.Errorf("%s: %s, want %s", kind, got, want)
		}
	}
	if got := domain.Deadline(domain.KindAccessRequest, seconds(3600)); got != time.Hour {
		t.Errorf("a shorter setting: %s", got)
	}
	if got := domain.Deadline(domain.KindRestoration, seconds(10*86400)); got != day {
		t.Errorf("a setting never lengthens: %s", got)
	}
	for kind, want := range map[string]bool{
		domain.KindAccessRequest: true, domain.KindToolReview: true, domain.KindReconciliation: false,
		domain.KindRestoration: false, domain.KindActionHold: false, domain.KindAdmission: false,
	} {
		if domain.Expires(kind) != want {
			t.Errorf("Expires(%s) = %v", kind, !want)
		}
	}
}

// TestHR177_DecidersComeFromPermissions: holds and restorations follow the
// approval rules; every other kind names the permission that decides it.
func TestHR177_DecidersComeFromPermissions(t *testing.T) {
	for kind, want := range map[string]td.Permission{
		domain.KindAdmission: td.PermAgentAdmit, domain.KindAccessRequest: td.PermGrantIssue,
		domain.KindToolReview: td.PermPackageActivate, domain.KindReconciliation: td.PermIncidentRespond,
	} {
		if p, ok := domain.DeciderPermission(kind); !ok || p != want {
			t.Errorf("%s: %s %v", kind, p, ok)
		}
	}
	for _, kind := range []string{domain.KindActionHold, domain.KindRestoration} {
		if _, ok := domain.DeciderPermission(kind); ok {
			t.Errorf("%s is decided under the approval rules", kind)
		}
	}
}

// TestHR176_AWorkloadCitesOnlyScopeDenials (decision 10): only a denial
// whose decisive reason a revision of the grant could change.
func TestHR176_AWorkloadCitesOnlyScopeDenials(t *testing.T) {
	for _, c := range []struct {
		decision, reason string
		want             bool
	}{
		{"DENY", "OPERATION_NOT_GRANTED", true},
		{"DENY", "TARGET_NOT_GRANTED", true},
		{"DENY", "DESTINATION_NOT_GRANTED", true},
		{"DENY", "GRANT_LIMIT_EXCEEDED", true},
		{"DENY", "OUTSIDE_TIME_WINDOW", true},
		{"DENY", "OUTSIDE_GUARDRAIL", false},
		{"DENY", "NO_GRANT", false},
		{"DENY", "BUDGET_EXHAUSTED", false},
		{"ALLOW", "OPERATION_NOT_GRANTED", false},
		{"REQUIRE_APPROVAL", "GRANT_REQUIRES_APPROVAL", false},
	} {
		if got := domain.ScopeDenial(c.decision, c.reason); got != c.want {
			t.Errorf("%s %s: %v", c.decision, c.reason, got)
		}
	}
}

// TestHR173_TheFirstNoticeGoesToTheNearestDeciders (decision 8): the
// nearest rank any decider has, at most 50; the next steps at a half and
// three quarters of the entry's time.
func TestHR173_TheFirstNoticeGoesToTheNearestDeciders(t *testing.T) {
	var cs []domain.Candidate
	for i := range 120 {
		cs = append(cs, domain.Candidate{User: ids.NewV7(), Rank: domain.RankBusinessUnit + i%2})
	}
	near := domain.Nearest(cs)
	if len(near) != domain.MaxRecipients || slices.ContainsFunc(near, func(c domain.Candidate) bool { return c.Rank != domain.RankBusinessUnit }) {
		t.Fatalf("nearest: %d", len(near))
	}
	if domain.Nearest(nil) != nil {
		t.Fatal("no deciders")
	}
	created := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	deadline := created.Add(time.Hour)
	c := domain.DefaultChain
	if domain.StepAt(c, 1, created, deadline) != created.Add(30*time.Minute) || domain.StepAt(c, 2, created, deadline) != created.Add(45*time.Minute) ||
		!domain.StepAt(c, 3, created, deadline).IsZero() {
		t.Fatal("the default chain's steps")
	}
	org := domain.Step{Scope: domain.ScopeOrg}
	if got := domain.Reach(org, []domain.Candidate{{Rank: 0}, {Rank: 2}, {Rank: 1}}); len(got) != 3 {
		t.Fatalf("an org-scope step reaches every decider: %d", len(got))
	}
	if got := domain.Reach(domain.Step{Scope: domain.ScopeBusinessUnit}, []domain.Candidate{{Rank: 0}, {Rank: 2}, {Rank: 1}}); len(got) != 2 {
		t.Fatalf("a business-unit step: %d", len(got))
	}
}

// TestHR173_ChainsOnlyWidenAndStayBeforeTheDeadline: a chain starts at 0%,
// has 1 to 5 steps at increasing times below 100%, and never narrows.
func TestHR173_ChainsOnlyWidenAndStayBeforeTheDeadline(t *testing.T) {
	if err := domain.ValidateChain(domain.DefaultChain); err != nil {
		t.Fatal(err)
	}
	near, bu := domain.ScopeNearest, domain.ScopeBusinessUnit
	for name, steps := range map[string][]domain.Step{
		"empty":         nil,
		"six steps":     {{0, near, false, false, true}, {10, near, false, false, false}, {20, near, false, false, false}, {30, bu, false, false, false}, {40, bu, false, false, false}, {50, bu, false, false, false}},
		"late start":    {{10, near, false, false, true}},
		"not later":     {{0, near, false, false, true}, {0, bu, false, false, false}},
		"at 100%":       {{0, near, false, false, true}, {100, bu, false, false, false}},
		"narrows":       {{0, bu, false, false, true}, {50, near, false, false, false}},
		"unknown scope": {{0, "TEAM", false, false, true}},
	} {
		if err := domain.ValidateChain(steps); !errors.Is(err, domain.ErrChainInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
