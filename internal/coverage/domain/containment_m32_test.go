// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// kubeBlocked are the kubernetes profile's probes, each blocked from an
// agent pod.
var kubeBlocked = []string{
	domain.ProbeKubeAPI, domain.ProbeKubelet, domain.ProbeNodeIP, domain.ProbeMetadata, domain.ProbeDNSCluster,
	domain.ProbeDNSExternal, domain.ProbeDirectHTTPS, domain.ProbeServiceOther, domain.ProbeIPv6,
}

// kubeTwins are the positive twins the control run in the release
// namespace reaches (metadata and IPv6 need none).
var kubeTwins = []string{
	domain.ProbeKubeAPI, domain.ProbeKubelet, domain.ProbeNodeIP, domain.ProbeDNSCluster, domain.ProbeDNSExternal,
	domain.ProbeDirectHTTPS, domain.ProbeServiceOther,
}

// kubeProbes is a passing kube closure's evidence: the agent pod's probes
// blocked, the edge's controls, and the control run's twins.
func kubeProbes() []domain.ProbeResult {
	var out []domain.ProbeResult
	for _, n := range kubeBlocked {
		out = append(out, domain.ProbeResult{Name: n, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Blocked})
	}
	for _, n := range kubeTwins {
		out = append(out, domain.ProbeResult{Name: n, Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable})
	}
	return append(out,
		domain.ProbeResult{Name: domain.ProbeEdgeMediated, Role: domain.RolePositiveControl, Expect: domain.Reachable, Observed: domain.Reachable},
		domain.ProbeResult{Name: domain.ProbeEdgeUnmappedRefused, Role: domain.RoleNegativeControl, Expect: domain.Blocked, Observed: domain.Blocked},
	)
}

func kubeChecks() []domain.ConfigCheck {
	return []domain.ConfigCheck{{ID: domain.CheckAdmissionEnforced, OK: true}, {ID: domain.CheckNetpolEgressGatewayOnly, OK: true}}
}

func without(ps []domain.ProbeResult, role, name string) []domain.ProbeResult {
	return slices.DeleteFunc(slices.Clone(ps), func(p domain.ProbeResult) bool { return p.Role == role && p.Name == name })
}

// TestHR742_AKubeClosureClosesOnlyWithEveryProbeTwinControlAndCheck: under
// the kubernetes profile every containment kind closes when every probe
// was blocked with its twin reachable, the edge's controls passed and both
// server checks are ok, without the sandbox's canary. Without one twin, one
// check, a control, or with one probe reachable, no kind closes.
func TestHR742_AKubeClosureClosesOnlyWithEveryProbeTwinControlAndCheck(t *testing.T) {
	v := domain.EvaluateIn(domain.ContainmentKubernetes, kubeProbes(), kubeChecks())
	if !v.Passed || !slices.Equal(v.Closed, domain.ContainmentKinds) || v.Canary {
		t.Fatalf("a full kube closure: %+v", v)
	}
	// The same evidence under the sandbox profile proves nothing: its
	// canary and its own probes are missing.
	if s := domain.Evaluate(kubeProbes(), kubeChecks()); s.Passed || len(s.Closed) != 0 {
		t.Errorf("kube evidence under the sandbox profile: %+v", s)
	}

	cases := map[string]struct {
		probes []domain.ProbeResult
		checks []domain.ConfigCheck
	}{
		"no admission check":     {kubeProbes(), []domain.ConfigCheck{{ID: domain.CheckNetpolEgressGatewayOnly, OK: true}}},
		"admission not ok":       {kubeProbes(), []domain.ConfigCheck{{ID: domain.CheckAdmissionEnforced}, {ID: domain.CheckNetpolEgressGatewayOnly, OK: true}}},
		"no NetworkPolicy check": {kubeProbes(), []domain.ConfigCheck{{ID: domain.CheckAdmissionEnforced, OK: true}}},
		"NetworkPolicy not ok":   {kubeProbes(), []domain.ConfigCheck{{ID: domain.CheckAdmissionEnforced, OK: true}, {ID: domain.CheckNetpolEgressGatewayOnly}}},
		"no kubelet twin":        {without(kubeProbes(), domain.RolePositiveControl, domain.ProbeKubelet), kubeChecks()},
		"no API server probe":    {without(kubeProbes(), domain.RoleProbe, domain.ProbeKubeAPI), kubeChecks()},
		"no edge_mediated":       {without(kubeProbes(), domain.RolePositiveControl, domain.ProbeEdgeMediated), kubeChecks()},
		"no negative control":    {without(kubeProbes(), domain.RoleNegativeControl, domain.ProbeEdgeUnmappedRefused), kubeChecks()},
		"cluster DNS answered": {append(kubeProbes(), domain.ProbeResult{
			Name: domain.ProbeDNSCluster, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Reachable,
		}), kubeChecks()},
		"a probe in error": {append(kubeProbes(), domain.ProbeResult{
			Name: domain.ProbeServiceOther, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: "error",
		}), kubeChecks()},
	}
	for name, c := range cases {
		if v := domain.EvaluateIn(domain.ContainmentKubernetes, c.probes, c.checks); len(v.Closed) != 0 {
			t.Errorf("%s: closed %v", name, v.Closed)
		}
	}
	// An unknown profile closes nothing.
	if v := domain.EvaluateIn("docker-desktop", kubeProbes(), kubeChecks()); v.Passed || len(v.Closed) != 0 {
		t.Errorf("an unknown profile: %+v", v)
	}
	if domain.ContainmentOf(domain.RuntimeKubernetes) != domain.ContainmentKubernetes || domain.ContainmentOf("runsc") != domain.ContainmentSandbox {
		t.Error("ContainmentOf")
	}
}

// kubeEnforced is evidence that computes ENFORCED from a kube closure of
// cluster prod, namespace agents, for an instance attested there.
func kubeEnforced() domain.Evidence {
	e := enforced()
	e.Closure.SandboxSession = ids.UUID{}
	e.Closure.Containment = domain.ContainmentKubernetes
	e.Closure.Kube = &domain.KubeScope{Cluster: "prod", Namespace: "agents"}
	e.Closure.Probes, e.Closure.ConfigChecks = kubeProbes(), kubeChecks()
	e.Instances = []domain.Instance{{ID: ids.NewV7(), Kube: &domain.KubeScope{Cluster: "prod", Namespace: "agents"}}}
	return e
}

// TestHR743_AKubeClosureCoversOnlyItsNamespaceAndLapses: a passing kube
// closure makes the scope ENFORCED for instances of its cluster and
// namespace only; an instance elsewhere, a sandboxed or unattested one, a
// failed closure or an expired one does not.
func TestHR743_AKubeClosureCoversOnlyItsNamespaceAndLapses(t *testing.T) {
	if r := domain.Compute(kubeEnforced()); r.State != domain.Enforced {
		t.Fatalf("a kube closure: %v %v", r.State, r.Reasons)
	}
	for name, edit := range map[string]func(e *domain.Evidence){
		"an instance in another namespace": func(e *domain.Evidence) {
			e.Instances = append(e.Instances, domain.Instance{ID: ids.NewV7(), Kube: &domain.KubeScope{Cluster: "prod", Namespace: "build"}})
		},
		"an instance in another cluster": func(e *domain.Evidence) {
			e.Instances = append(e.Instances, domain.Instance{ID: ids.NewV7(), Kube: &domain.KubeScope{Cluster: "staging", Namespace: "agents"}})
		},
		"an instance with no attestation": func(e *domain.Evidence) {
			e.Instances = append(e.Instances, domain.Instance{ID: ids.NewV7()})
		},
		"a sandboxed instance": func(e *domain.Evidence) {
			s := ids.NewV7()
			e.Instances = append(e.Instances, domain.Instance{ID: ids.NewV7(), SandboxSession: &s})
		},
		"a failed probe": func(e *domain.Evidence) {
			e.Closure.Probes = append(e.Closure.Probes, domain.ProbeResult{
				Name: domain.ProbeKubeAPI, Role: domain.RoleProbe, Expect: domain.Blocked, Observed: domain.Reachable,
			})
		},
		"a failed server check": func(e *domain.Evidence) {
			e.Closure.ConfigChecks = []domain.ConfigCheck{{ID: domain.CheckAdmissionEnforced, OK: true}, {ID: domain.CheckNetpolEgressGatewayOnly}}
		},
		"an expired closure": func(e *domain.Evidence) { e.Closure.ExpiresAt = e.Now.Add(-1) },
	} {
		e := kubeEnforced()
		edit(&e)
		if r := domain.Compute(e); r.State == domain.Enforced {
			t.Errorf("%s: still ENFORCED", name)
		}
	}
}
