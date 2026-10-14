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

// TestHR210_ClosurePassesOnlyWithTheNamedControlsAndTheCanary: a full
// catalog passes and closes every kind; without a named positive or
// negative control nothing is closed at all, without the canary the
// closure fails, and each route kind closes only by its own probes (F458):
// a passed closure that lacks a probe leaves its kinds open.
func TestHR210_ClosurePassesOnlyWithTheNamedControlsAndTheCanary(t *testing.T) {
	if v := domain.Evaluate(passingProbes(), passingChecks()); !v.Passed || len(v.Closed) != len(domain.ContainmentKinds) ||
		len(v.Failed) != 0 {
		t.Fatalf("full catalog: %+v", v)
	}
	without := func(role, name string) []domain.ProbeResult {
		return slices.DeleteFunc(passingProbes(), func(p domain.ProbeResult) bool { return p.Role == role && p.Name == name })
	}
	for _, c := range [][2]string{
		{domain.RolePositiveControl, domain.ProbeEdgeMediated},
		{domain.RolePositiveControl, domain.ProbeCanaryControl},
		{domain.RoleNegativeControl, domain.ProbeEdgeUnmappedRefused},
	} {
		if v := domain.Evaluate(without(c[0], c[1]), passingChecks()); v.Passed || len(v.Closed) != 0 ||
			!slices.Contains(v.Failed, c[1]) {
			t.Errorf("without %s: %+v", c[1], v)
		}
	}
	// Another control under a required control's role does not stand in.
	renamed := passingProbes()
	for i := range renamed {
		if renamed[i].Name == domain.ProbeEdgeUnmappedRefused {
			renamed[i].Name = "something_refused"
		}
	}
	if v := domain.Evaluate(renamed, passingChecks()); v.Passed || len(v.Closed) != 0 {
		t.Errorf("an unnamed negative control: %+v", v)
	}
	if v := domain.Evaluate(without(domain.RoleCanary, domain.ProbeExternalCanary), passingChecks()); v.Passed ||
		slices.Contains(v.Closed, domain.KindDirectAPI) {
		t.Errorf("without the canary: %+v", v)
	}
	// Revoking a PAT (pat_push blocked) does not close SSH (F458).
	ssh := without(domain.RoleProbe, domain.ProbeSSHPush)
	if v := domain.Evaluate(ssh, passingChecks()); !v.Passed || slices.Contains(v.Closed, domain.KindGitSSH) ||
		slices.Contains(v.Closed, domain.KindCredential) || !slices.Contains(v.Closed, domain.KindHost) {
		t.Errorf("without the SSH push probe: %+v", v)
	}
	// A probe that expects "reachable" never closes a route.
	odd := passingProbes()
	odd[0].Expect, odd[0].Observed = domain.Reachable, domain.Reachable
	if v := domain.Evaluate(odd, passingChecks()); slices.Contains(v.Closed, domain.KindDirectAPI) {
		t.Errorf("a reachable %s closed a route", odd[0].Name)
	}
}

// TestHR210_AProbeClosesOnlyWithItsPositiveTwin: a probe that never saw
// the route open on the control network (ICMP without NET_RAW reports
// "blocked" everywhere) closes nothing (decision 15). IPv6 and the
// metadata service may not exist even on an open network, so they close
// on their blocked result alone.
func TestHR210_AProbeClosesOnlyWithItsPositiveTwin(t *testing.T) {
	for name, open := range map[string][]domain.RouteKind{
		domain.ProbeICMP:        {domain.KindDirectAPI},
		domain.ProbeHostGateway: {domain.KindDirectAPI, domain.KindHost},
		domain.ProbeDirectSSH:   {domain.KindGitSSH, domain.KindDelegated, domain.KindIntermediary},
		domain.ProbePATPush:     {domain.KindCredential, domain.KindBrowser},
	} {
		probes := slices.DeleteFunc(passingProbes(), func(p domain.ProbeResult) bool {
			return p.Role == domain.RolePositiveControl && p.Name == name
		})
		v := domain.Evaluate(probes, passingChecks())
		if !v.Passed || len(v.Closed) != len(domain.ContainmentKinds)-len(open) ||
			slices.ContainsFunc(open, func(k domain.RouteKind) bool { return slices.Contains(v.Closed, k) }) {
			t.Errorf("%s without its twin: %+v", name, v)
		}
	}
	// The canary's twin is a required control: without it nothing closes.
	canary := slices.DeleteFunc(passingProbes(), func(p domain.ProbeResult) bool { return p.Name == domain.ProbeCanaryControl })
	if v := domain.Evaluate(canary, passingChecks()); v.Passed || len(v.Closed) != 0 {
		t.Errorf("the canary without its twin: %+v", v)
	}
	for _, name := range []string{domain.ProbeIPv6, domain.ProbeMetadata} {
		probes := slices.DeleteFunc(passingProbes(), func(p domain.ProbeResult) bool {
			return p.Role == domain.RolePositiveControl && p.Name == name
		})
		if v := domain.Evaluate(probes, passingChecks()); !v.Passed {
			t.Errorf("%s without a twin: %+v", name, v)
		}
	}
}

// TestHR210_TheHostRouteClosesOnTheConfigurationChecks: the Docker socket
// is never mounted, so its probe cannot show it open; the host route
// closes only when pclaw found neither the socket nor a host bind in the
// agent container, and a failed check fails the closure.
func TestHR210_TheHostRouteClosesOnTheConfigurationChecks(t *testing.T) {
	for _, id := range []string{domain.CheckNoDockerSocket, domain.CheckNoHostBind} {
		missing := slices.DeleteFunc(passingChecks(), func(c domain.ConfigCheck) bool { return c.ID == id })
		if v := domain.Evaluate(passingProbes(), missing); !v.Passed || slices.Contains(v.Closed, domain.KindHost) {
			t.Errorf("without %s: %+v", id, v)
		}
		failed := passingChecks()
		for i := range failed {
			if failed[i].ID == id {
				failed[i].OK = false
			}
		}
		if v := domain.Evaluate(passingProbes(), failed); v.Passed || slices.Contains(v.Closed, domain.KindHost) ||
			!slices.Contains(v.Failed, "config:"+id) {
			t.Errorf("%s failed: %+v", id, v)
		}
	}
	extra := append(passingChecks(), domain.ConfigCheck{ID: "agent_read_only_root", OK: false})
	if v := domain.Evaluate(passingProbes(), extra); v.Passed {
		t.Errorf("a failed check of another kind passed: %+v", v)
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
		if v := domain.Evaluate(probes, passingChecks()); v.Passed || !slices.Contains(v.Failed, bad.Name) {
			t.Fatalf("%s observed %q: %+v", bad.Name, bad.Observed, v)
		}
	})
}

// passingProbes is a full passing catalog (see closure.go): every probe
// blocked in the sandbox, its positive twin reachable on the open control
// network, and the named controls and canary.
func passingProbes() []domain.ProbeResult {
	var out []domain.ProbeResult
	for _, n := range []string{
		domain.ProbeDNSExternal, domain.ProbeDNSDockerResolver, domain.ProbeIPv6, domain.ProbeICMP, domain.ProbeDirectHTTPS,
		domain.ProbeMetadata, domain.ProbeHostGateway, domain.ProbeDockerSocket, domain.ProbeDirectSSH, domain.ProbeSSHPush,
		domain.ProbePATPush,
	} {
		out = append(out, domain.ProbeResult{Name: n, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked})
		if n != domain.ProbeDockerSocket {
			out = append(out, domain.ProbeResult{
				Name: n, Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable,
			})
		}
	}
	return append(out,
		domain.ProbeResult{Name: domain.ProbeEdgeMediated, Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
		domain.ProbeResult{Name: domain.ProbeCanaryControl, Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
		domain.ProbeResult{Name: domain.ProbeEdgeUnmappedRefused, Role: domain.RoleNegativeControl, Expect: domain.Blocked, Observed: domain.Blocked},
		domain.ProbeResult{Name: domain.ProbeExternalCanary, Role: domain.RoleCanary, Expect: domain.Blocked, Observed: domain.Blocked},
	)
}

// passingChecks are pclaw's passing configuration checks.
func passingChecks() []domain.ConfigCheck {
	return []domain.ConfigCheck{{ID: domain.CheckNoDockerSocket, OK: true}, {ID: domain.CheckNoHostBind, OK: true}}
}
