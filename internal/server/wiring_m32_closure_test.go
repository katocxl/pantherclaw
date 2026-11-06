// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"slices"
	"strings"
	"testing"

	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// chartPolicy is the agent NetworkPolicy the chart renders (D965, D965a):
// every pod, egress to the release namespace's gateway pods on 8443 and its
// api pods on 8080, TCP.
func chartPolicy() kube.NetworkPolicy {
	release := func(component string) kube.Peer {
		return kube.Peer{
			NamespaceSelector: &kube.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "pantherclaw"}},
			PodSelector:       &kube.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/component": component}},
		}
	}
	return kube.NetworkPolicy{
		Name: "pantherclaw-agents", PodSelector: kube.LabelSelector{}, PolicyTypes: []string{"Ingress", "Egress"},
		Egress: []kube.EgressRule{
			{To: []kube.Peer{release("gateway")}, Ports: []kube.Port{{Protocol: "TCP", Port: "8443"}}},
			{To: []kube.Peer{release("api")}, Ports: []kube.Port{{Protocol: "TCP", Port: "8080"}}},
		},
	}
}

// TestHR742_TheNetworkPolicyCheckAcceptsOnlyTheGatewayShape: the chart's
// policy, its external-API form (an ipBlock of at most /24 or /64) and an
// ingress-only policy beside it pass; no policy for every pod, a rule open
// to every peer or port, DNS, UDP, a named port or range, a peer in every
// namespace or of another component, a wide or excepted ipBlock, or a
// selector expression fails.
func TestHR742_TheNetworkPolicyCheckAcceptsOnlyTheGatewayShape(t *testing.T) {
	if why := netpolGatewayOnly([]kube.NetworkPolicy{chartPolicy()}); why != "" {
		t.Fatalf("the chart's policy: %s", why)
	}
	external := chartPolicy()
	external.Egress[1] = kube.EgressRule{To: []kube.Peer{{CIDR: "203.0.113.10/32"}, {CIDR: "2001:db8::/64"}}, Ports: []kube.Port{{Port: "443"}}}
	ingressOnly := kube.NetworkPolicy{Name: "from-ingress", PolicyTypes: []string{"Ingress"}, Egress: []kube.EgressRule{{}}}
	if why := netpolGatewayOnly([]kube.NetworkPolicy{external, ingressOnly}); why != "" {
		t.Errorf("external API and an ingress-only policy: %s", why)
	}
	implicit := chartPolicy()
	implicit.PolicyTypes = nil
	if why := netpolGatewayOnly([]kube.NetworkPolicy{implicit}); why != "" {
		t.Errorf("policyTypes implied by egress rules: %s", why)
	}

	edit := func(f func(np *kube.NetworkPolicy)) []kube.NetworkPolicy {
		np := chartPolicy()
		f(&np)
		return []kube.NetworkPolicy{np}
	}
	peer := func(f func(p *kube.Peer)) []kube.NetworkPolicy {
		return edit(func(np *kube.NetworkPolicy) { f(&np.Egress[0].To[0]) })
	}
	cases := map[string][]kube.NetworkPolicy{
		"no policy": nil,
		"a policy for some pods only": edit(func(np *kube.NetworkPolicy) {
			np.PodSelector = kube.LabelSelector{MatchLabels: map[string]string{"app": "x"}}
		}),
		"an ingress-only policy alone": edit(func(np *kube.NetworkPolicy) { np.PolicyTypes = []string{"Ingress"} }),
		"every peer":                   edit(func(np *kube.NetworkPolicy) { np.Egress[0].To = nil }),
		"every port":                   edit(func(np *kube.NetworkPolicy) { np.Egress[0].Ports = nil }),
		"DNS": edit(func(np *kube.NetworkPolicy) {
			np.Egress[0].Ports = append(np.Egress[0].Ports, kube.Port{Protocol: "TCP", Port: "53"})
		}),
		"UDP":                   edit(func(np *kube.NetworkPolicy) { np.Egress[0].Ports[0].Protocol = "UDP" }),
		"a named port":          edit(func(np *kube.NetworkPolicy) { np.Egress[0].Ports[0].Port = "https" }),
		"a port range":          edit(func(np *kube.NetworkPolicy) { np.Egress[0].Ports[0].EndPort = 9000 }),
		"every namespace":       peer(func(p *kube.Peer) { p.NamespaceSelector = &kube.LabelSelector{} }),
		"no namespace selector": peer(func(p *kube.Peer) { p.NamespaceSelector = nil }),
		"another component": peer(func(p *kube.Peer) {
			p.PodSelector = &kube.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/component": "canary"}}
		}),
		"a selector expression": peer(func(p *kube.Peer) { p.PodSelector.Expressions = 1 }),
		"a /16":                 peer(func(p *kube.Peer) { *p = kube.Peer{CIDR: "10.0.0.0/16"} }),
		"everything":            peer(func(p *kube.Peer) { *p = kube.Peer{CIDR: "0.0.0.0/0"} }),
		"an IPv6 /48":           peer(func(p *kube.Peer) { *p = kube.Peer{CIDR: "2001:db8::/48"} }),
		"an ipBlock with except": peer(func(p *kube.Peer) {
			*p = kube.Peer{CIDR: "10.0.0.0/24", Except: []string{"10.0.0.1/32"}}
		}),
		"a malformed ipBlock": peer(func(p *kube.Peer) { *p = kube.Peer{CIDR: "10.0.0.300/32"} }),
		"a second policy open to everything": append([]kube.NetworkPolicy{chartPolicy()}, kube.NetworkPolicy{
			Name: "allow-all", PolicyTypes: []string{"Egress"}, Egress: []kube.EgressRule{{}},
		}),
	}
	for name, nps := range cases {
		if why := netpolGatewayOnly(nps); why == "" {
			t.Errorf("%s: passed", name)
		}
	}
}

// TestHR741_ImageDigestsComeFromThePodsImageIDs: digestOf reads the digest
// of every image id form the kubelet reports and nothing else.
func TestHR741_ImageDigestsComeFromThePodsImageIDs(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	for _, id := range []string{d, "ghcr.io/katocxl/pantherclaw-edge@" + d, "docker-pullable://ghcr.io/katocxl/pantherclaw-edge@" + d} {
		if got := digestOf(id); got != d {
			t.Errorf("digestOf(%q) = %q", id, got)
		}
	}
	for _, id := range []string{"", "ghcr.io/katocxl/pantherclaw-edge:v1", "sha256:abc", "sha256:" + strings.Repeat("AB", 32), d + "x"} {
		if got := digestOf(id); got != "" {
			t.Errorf("digestOf(%q) = %q, want none", id, got)
		}
	}
}

// TestHR743_TheMappedConnectionsAreTheHostsTheEdgeMediated: only passed
// edge_mediated controls name a host, once, lower-cased; a failed one, a
// probe of that name or a detail that is not a plain host names nothing.
func TestHR743_TheMappedConnectionsAreTheHostsTheEdgeMediated(t *testing.T) {
	ok := func(detail string) report.Result {
		return report.Result{Name: covdomain.ProbeEdgeMediated, Role: report.RolePositive, Expect: report.Reachable, Observed: report.Reachable, Detail: detail}
	}
	failed := ok("https://payments.example through the edge")
	failed.Observed = report.Blocked
	probeRole := ok("https://evil.example through the edge")
	probeRole.Role = report.RoleProbe
	got := mappedHosts([]report.Result{
		ok("https://API.GitHub.com through the edge"), ok("https://api.github.com through the edge"), failed, probeRole,
		ok("https://user@evil.example through the edge"), ok("https://evil.example:8443 through the edge"),
		ok("https://evil.example/path through the edge"), ok("http://plain.example through the edge"),
	})
	if !slices.Equal(got, []string{"api.github.com"}) {
		t.Errorf("mapped hosts %v, want [api.github.com]", got)
	}
}
