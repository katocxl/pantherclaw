// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
)

func TestProbePassesOnlyOnTheExpectedOutcome(t *testing.T) {
	for _, c := range []struct {
		expect, observed string
		want             bool
	}{
		{domain.Blocked, domain.Blocked, true},
		{domain.Reachable, domain.Reachable, true},
		{domain.Blocked, domain.Reachable, false},
		{domain.Blocked, domain.ProbeErr, false},
		{domain.ProbeErr, domain.ProbeErr, false},
		{"", "", false},
	} {
		if got := (domain.ProbeResult{Expect: c.expect, Observed: c.observed}).Passed(); got != c.want {
			t.Errorf("expect %q observed %q: passed %v", c.expect, c.observed, got)
		}
	}
}

// TestHR210_ClosurePassesOnlyWithBothControlsAndTheCanary: a full catalog
// passes; without a positive or negative control nothing is closed at all,
// a failed canary fails the closure, and each route kind closes only by
// its own probes (F458).
func TestHR210_ClosurePassesOnlyWithBothControlsAndTheCanary(t *testing.T) {
	if v := domain.Evaluate(passingProbes()); !v.Passed || len(v.Closed) != len(domain.ContainmentKinds) || len(v.Failed) != 0 {
		t.Fatalf("full catalog: %+v", v)
	}
	without := func(role string) []domain.ProbeResult {
		return slices.DeleteFunc(passingProbes(), func(p domain.ProbeResult) bool { return p.Role == role })
	}
	for _, role := range []string{domain.RolePositiveControl, domain.RoleNegativeControl} {
		if v := domain.Evaluate(without(role)); v.Passed || len(v.Closed) != 0 {
			t.Errorf("without a %s: %+v", role, v)
		}
	}
	if v := domain.Evaluate(without(domain.RoleCanary)); v.Passed || slices.Contains(v.Closed, domain.KindDirectAPI) {
		t.Errorf("without the canary: %+v", v)
	}
	// Revoking a PAT (pat_push blocked) does not close SSH (F458).
	ssh := slices.DeleteFunc(passingProbes(), func(p domain.ProbeResult) bool { return p.Name == domain.ProbeSSHPush })
	if v := domain.Evaluate(ssh); v.Passed || slices.Contains(v.Closed, domain.KindGitSSH) || !slices.Contains(v.Closed, domain.KindHost) {
		t.Errorf("without the SSH push probe: %+v", v)
	}
	// A probe that expects "reachable" never closes a route.
	odd := passingProbes()
	odd[0].Expect, odd[0].Observed = domain.Reachable, domain.Reachable
	if v := domain.Evaluate(odd); v.Passed {
		t.Errorf("a reachable %s closed a route", odd[0].Name)
	}
}

// TestHR210_AnyFailedResultFailsTheClosure: flipping any one result of a
// passing catalog, or repeating it with another outcome, fails the
// closure.
func TestHR210_AnyFailedResultFailsTheClosure(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		probes := passingProbes()
		i := rapid.IntRange(0, len(probes)-1).Draw(t, "i")
		bad := probes[i]
		bad.Observed = rapid.SampledFrom([]string{domain.ProbeErr, "", "unknown"}).Draw(t, "observed")
		if rapid.Bool().Draw(t, "repeat") {
			probes = append(probes, bad)
		} else {
			probes[i] = bad
		}
		if v := domain.Evaluate(probes); v.Passed || !slices.Contains(v.Failed, bad.Name) {
			t.Fatalf("%s observed %q: %+v", bad.Name, bad.Observed, v)
		}
	})
}

// passingProbes is a full passing probe catalog (see closure.go).
func passingProbes() []domain.ProbeResult {
	var out []domain.ProbeResult
	for _, n := range []string{
		domain.ProbeDNSExternal, domain.ProbeDNSDockerResolver, domain.ProbeIPv6, domain.ProbeICMP, domain.ProbeDirectHTTPS,
		domain.ProbeMetadata, domain.ProbeHostGateway, domain.ProbeDockerSocket, domain.ProbeDirectSSH, domain.ProbeSSHPush,
		domain.ProbePATPush,
	} {
		out = append(out, domain.ProbeResult{Name: n, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked})
	}
	return append(out,
		domain.ProbeResult{Name: "edge_mediated", Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
		domain.ProbeResult{Name: "edge_unmapped_refused", Role: domain.RoleNegativeControl, Expect: domain.Blocked, Observed: domain.Blocked},
		domain.ProbeResult{Name: domain.ProbeExternalCanary, Role: domain.RoleCanary, Expect: domain.Blocked, Observed: domain.Blocked},
	)
}
