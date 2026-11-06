// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"slices"
	"strings"
	"testing"

	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/sandbox/probe"
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

// chartAdmission is the admission configuration the chart renders beside
// chartPolicy: the release namespace, the gateway and api ports, and the
// external API's CIDRs on the API Service port.
func chartAdmission() AdmissionConfig {
	return AdmissionConfig{
		ReleaseNamespace: "pantherclaw", GatewayPort: 8443, APIPort: 8080,
		APIEgressCIDRs: []string{"203.0.113.10/32", "2001:db8::/64"}, APIEgressPort: 443,
	}
}

// TestHR742_TheNetworkPolicyCheckAcceptsOnlyTheGatewayShape: the chart's
// policy, its external-API form (a configured apiEgressCIDR) and an
// ingress-only policy beside it pass; no policy for every pod, a rule open
// to every peer or port, DNS, UDP, a named port or range, a peer in every
// namespace, another namespace or of another component, a port other than
// its peer's, an unconfigured or excepted ipBlock, a selector expression,
// or a configuration without the release namespace fails (D1218 M1).
func TestHR742_TheNetworkPolicyCheckAcceptsOnlyTheGatewayShape(t *testing.T) {
	if why := netpolGatewayOnly([]kube.NetworkPolicy{chartPolicy()}, chartAdmission()); why != "" {
		t.Fatalf("the chart's policy: %s", why)
	}
	external := chartPolicy()
	external.Egress[1] = kube.EgressRule{To: []kube.Peer{{CIDR: "203.0.113.10/32"}, {CIDR: "2001:db8::/64"}}, Ports: []kube.Port{{Port: "443"}}}
	ingressOnly := kube.NetworkPolicy{Name: "from-ingress", PolicyTypes: []string{"Ingress"}, Egress: []kube.EgressRule{{}}}
	if why := netpolGatewayOnly([]kube.NetworkPolicy{external, ingressOnly}, chartAdmission()); why != "" {
		t.Errorf("external API and an ingress-only policy: %s", why)
	}
	implicit := chartPolicy()
	implicit.PolicyTypes = nil
	if why := netpolGatewayOnly([]kube.NetworkPolicy{implicit}, chartAdmission()); why != "" {
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
		// D1218 M1: exact namespace, port and CIDR.
		"another namespace": peer(func(p *kube.Peer) {
			p.NamespaceSelector = &kube.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "attacker-ns"}}
		}),
		"another port":                edit(func(np *kube.NetworkPolicy) { np.Egress[0].Ports[0].Port = "3128" }),
		"the gateway on the api port": edit(func(np *kube.NetworkPolicy) { np.Egress[0].Ports[0].Port = "8080" }),
		"the gateway beside a second port": edit(func(np *kube.NetworkPolicy) {
			np.Egress[0].Ports = append(np.Egress[0].Ports, kube.Port{Protocol: "TCP", Port: "8080"})
		}),
		"the api and the gateway in one rule": edit(func(np *kube.NetworkPolicy) {
			np.Egress[0].To = append(np.Egress[0].To, np.Egress[1].To[0])
		}),
		"a second label on the pod selector": peer(func(p *kube.Peer) { p.PodSelector.MatchLabels["app"] = "x" }),
		"an unconfigured /32":                peer(func(p *kube.Peer) { *p = kube.Peer{CIDR: "198.51.100.7/32"} }),
		"an unconfigured /24":                peer(func(p *kube.Peer) { *p = kube.Peer{CIDR: "198.51.100.0/24"} }),
		"a configured CIDR on another port": edit(func(np *kube.NetworkPolicy) {
			np.Egress[1] = kube.EgressRule{To: []kube.Peer{{CIDR: "203.0.113.10/32"}}, Ports: []kube.Port{{Port: "3128"}}}
		}),
	}
	for name, nps := range cases {
		if why := netpolGatewayOnly(nps, chartAdmission()); why == "" {
			t.Errorf("%s: passed", name)
		}
	}
	unconfigured := chartAdmission()
	unconfigured.ReleaseNamespace = ""
	if why := netpolGatewayOnly([]kube.NetworkPolicy{chartPolicy()}, unconfigured); why == "" {
		t.Error("no release namespace configured: passed")
	}
}

// TestHR742_ProbeTargetsAreThePodsNodeTheControlsAndTheCatalogs: a
// passing probe result whose target is the pod's node (kubelet, node_ip),
// the control twin's (kube_api, service_other, dns_cluster) or the
// catalog's fixed one is accepted; a forged node IP, API server, Service,
// nameserver or fixed target is refused with K8S_CLOSURE_REJECTED (D1218
// M2, T-339). A failed result and, with no control closure, the
// twin-checked probes are not checked: they close nothing.
func TestHR742_ProbeTargetsAreThePodsNodeTheControlsAndTheCatalogs(t *testing.T) {
	// Results as the probe writes them (D1218a N1): a timed-out probe's
	// detail is "<target>: context deadline exceeded".
	blocked := func(name, target string) covdomain.ProbeResult {
		return probeResults([]report.Result{probe.Result(name, report.RoleProbe, report.Blocked, target, context.DeadlineExceeded)})[0]
	}
	twin := func(name, target string) covdomain.ProbeResult {
		return probeResults([]report.Result{probe.Result(name, report.RolePositive, report.Reachable, target, nil)})[0]
	}
	twins := []covdomain.ProbeResult{
		twin(covdomain.ProbeKubeAPI, "10.96.0.1:443"), twin(covdomain.ProbeServiceOther, "10.96.200.20:8080"),
		twin(covdomain.ProbeDNSCluster, "udp 10.96.0.10:53"), twin(covdomain.ProbeDNSCluster, "tcp 10.96.0.10:53"),
		twin(covdomain.ProbeKubelet, "10.0.0.9:10250"),
	}
	honest := []covdomain.ProbeResult{
		blocked(covdomain.ProbeKubeAPI, "10.96.0.1:443"),
		blocked(covdomain.ProbeKubelet, "10.0.0.5:10250"), blocked(covdomain.ProbeKubelet, "10.0.0.5:10255"),
		blocked(covdomain.ProbeNodeIP, "10.0.0.5:22"), blocked(covdomain.ProbeNodeIP, "10.0.0.5:443"),
		blocked(covdomain.ProbeServiceOther, "10.96.200.20:8080"),
		blocked(covdomain.ProbeDNSCluster, "udp 10.96.0.10:53"), blocked(covdomain.ProbeDNSCluster, "tcp 10.96.0.10:53"),
		blocked(covdomain.ProbeDirectHTTPS, "1.1.1.1:443"), blocked(covdomain.ProbeDNSExternal, "udp 8.8.8.8:53"),
		blocked(covdomain.ProbeMetadata, "169.254.169.254:80"), blocked(covdomain.ProbeIPv6, "an IPv6 address or default route"),
	}
	if err := targetsMatch(honest, "10.0.0.5", twins); err != nil {
		t.Fatalf("honest targets: %v", err)
	}
	if d := honest[0].Detail; d != "10.96.0.1:443: context deadline exceeded" {
		t.Fatalf("the probe's detail is %q", d)
	}
	forged := map[string]covdomain.ProbeResult{
		"a forged node IP for the kubelet":   blocked(covdomain.ProbeKubelet, "192.0.2.1:10250"),
		"the control's node for the kubelet": blocked(covdomain.ProbeKubelet, "10.0.0.9:10250"),
		"a forged node IP":                   blocked(covdomain.ProbeNodeIP, "192.0.2.1:22"),
		"a forged API server":                blocked(covdomain.ProbeKubeAPI, "192.0.2.3:443"),
		"a forged Service":                   blocked(covdomain.ProbeServiceOther, "192.0.2.2:8080"),
		"a forged nameserver":                blocked(covdomain.ProbeDNSCluster, "udp 192.0.2.53:53"),
		"a forged direct target":             blocked(covdomain.ProbeDirectHTTPS, "192.0.2.4:443"),
		"a forged metadata target":           blocked(covdomain.ProbeMetadata, "192.0.2.5:80"),
	}
	for name, r := range forged {
		err := targetsMatch(append(slices.Clone(honest), r), "10.0.0.5", twins)
		if err == nil || !strings.Contains(err.Error(), "K8S_CLOSURE_REJECTED") {
			t.Errorf("%s: %v, want K8S_CLOSURE_REJECTED", name, err)
		}
	}
	if err := targetsMatch(honest, "", twins); err == nil {
		t.Error("an unknown node IP: accepted")
	}
	failed := blocked(covdomain.ProbeKubeAPI, "192.0.2.3:443")
	failed.Observed = report.Reachable
	if err := targetsMatch(append(slices.Clone(honest), failed), "10.0.0.5", twins); err != nil {
		t.Errorf("a failed result with another target: %v", err)
	}
	if err := targetsMatch([]covdomain.ProbeResult{blocked(covdomain.ProbeKubeAPI, "192.0.2.3:443")}, "10.0.0.5", nil); err != nil {
		t.Errorf("no control closure: %v", err)
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
	ok := func(target string) report.Result {
		return probe.Result(covdomain.ProbeEdgeMediated, report.RolePositive, report.Reachable, target, nil)
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
