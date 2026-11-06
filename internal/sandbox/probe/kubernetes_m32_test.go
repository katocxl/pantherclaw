// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"context"
	"slices"
	"testing"

	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

func kubeEnv(m map[string]string) func(string) string {
	base := map[string]string{
		"KUBERNETES_SERVICE_HOST": "10.96.0.1", "KUBERNETES_SERVICE_PORT": "443",
		EnvHostIP: "10.0.0.7", EnvCanaryIP: "10.96.200.12", EnvPodName: "probe-1", EnvNamespace: "agents",
		EnvAgentHosts: "api.github.com, payments.example",
	}
	for k, v := range m {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

// TestHR742_TheKubernetesCatalogIsTheProfilesContract: a sandbox run tries
// every probe the kubernetes profile closes on, expected blocked, plus the
// edge's two controls; a control run tries the positive twins of every
// probe that needs one, expected reachable, and nothing through the edge.
// A run without the node or canary address, or of another kind, does not
// start.
func TestHR742_TheKubernetesCatalogIsTheProfilesContract(t *testing.T) {
	c, err := KubeConfigFromEnv(report.KindSandbox, kubeEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	c.Nameservers = []string{"10.96.0.10"}
	if c.APIServer != "10.96.0.1:443" || c.CanaryService != "10.96.200.12:8080" || !slices.Equal(c.AgentHosts, []string{"api.github.com", "payments.example"}) {
		t.Fatalf("config %+v", c)
	}
	names := map[string]map[string]string{}
	for _, p := range kubeCatalog(c, "m") {
		if names[p.role] == nil {
			names[p.role] = map[string]string{}
		}
		names[p.role][p.name] = p.expect
	}
	for _, n := range []string{
		covdomain.ProbeKubeAPI, covdomain.ProbeKubelet, covdomain.ProbeNodeIP, covdomain.ProbeMetadata, covdomain.ProbeDNSCluster,
		covdomain.ProbeDNSExternal, covdomain.ProbeDirectHTTPS, covdomain.ProbeServiceOther, covdomain.ProbeIPv6,
	} {
		if names[report.RoleProbe][n] != report.Blocked {
			t.Errorf("the sandbox run does not try %s expected blocked", n)
		}
	}
	if names[report.RolePositive][covdomain.ProbeEdgeMediated] != report.Reachable ||
		names[report.RoleNegative][covdomain.ProbeEdgeUnmappedRefused] != report.Blocked {
		t.Errorf("the edge's controls: %v", names)
	}

	ctl, err := KubeConfigFromEnv(report.KindControl, kubeEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctl.Nameservers = []string{"10.96.0.10"}
	twins := map[string]bool{}
	for _, p := range kubeCatalog(ctl, "m") {
		if p.role != report.RolePositive || p.expect != report.Reachable {
			t.Errorf("control run probe %s is %s/%s, want a reachable positive twin", p.name, p.role, p.expect)
		}
		twins[p.name] = true
	}
	for _, n := range []string{
		covdomain.ProbeKubeAPI, covdomain.ProbeKubelet, covdomain.ProbeNodeIP, covdomain.ProbeDNSCluster,
		covdomain.ProbeDNSExternal, covdomain.ProbeDirectHTTPS, covdomain.ProbeServiceOther,
	} {
		if !twins[n] {
			t.Errorf("the control run has no twin of %s", n)
		}
	}
	if twins[covdomain.ProbeEdgeMediated] || twins[covdomain.ProbeMetadata] || twins[covdomain.ProbeIPv6] {
		t.Errorf("the control run tries %v", twins)
	}

	for name, env := range map[string]map[string]string{
		"no node IP":    {EnvHostIP: ""},
		"no canary":     {EnvCanaryIP: "pantherclaw-canary"},
		"no API server": {"KUBERNETES_SERVICE_HOST": ""},
		"a bad node IP": {EnvHostIP: "node-1"},
	} {
		if _, err := KubeConfigFromEnv(report.KindSandbox, kubeEnv(env)); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	if _, err := KubeConfigFromEnv(report.KindCanary, kubeEnv(nil)); err == nil {
		t.Error("a canary-kind run started")
	}
	// No resolver: dns_cluster is an error, which never passes.
	c.Nameservers = nil
	for _, p := range kubeCatalog(c, "m") {
		if p.name == covdomain.ProbeDNSCluster && observe(p.run(t.Context())) != report.Error {
			t.Error("dns_cluster without a resolver is not an error")
		}
	}
}

// TestHR742_EveryKubernetesResultNamesItsTarget: the probe's writer puts
// each probe's catalog target in Target and the target with its error in
// Detail, for every result of both kinds (D1218a N1).
func TestHR742_EveryKubernetesResultNamesItsTarget(t *testing.T) {
	for _, kind := range []string{report.KindSandbox, report.KindControl} {
		c, err := KubeConfigFromEnv(kind, kubeEnv(nil))
		if err != nil {
			t.Fatal(err)
		}
		c.Nameservers = []string{"10.96.0.10"}
		ps := kubeCatalog(c, "m")
		for i := range ps {
			ps[i].run = func(context.Context) error { return context.DeadlineExceeded }
		}
		rs := runProbes(t.Context(), ps)
		for i, r := range rs {
			if r.Target == "" || r.Target != ps[i].target || r.Detail != ps[i].target+": "+context.DeadlineExceeded.Error() {
				t.Errorf("%s %s: target %q detail %q", kind, r.Name, r.Target, r.Detail)
			}
		}
		if kind == report.KindSandbox && !slices.ContainsFunc(rs, func(r report.Result) bool { return r.Target == "10.0.0.7:10250" }) {
			t.Errorf("no kubelet target on the node: %+v", rs)
		}
	}
}
