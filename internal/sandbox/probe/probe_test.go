// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

func config() Config {
	return Config{
		Format: ConfigFormat, Kind: report.KindSandbox, KeyFile: "/pc/key.json",
		Report: report.Report{Session: "s-1", Nonce: "nonce-0123456789abcdef"},
		Edge:   "pc-edge-1:3128", CAFile: "/pc/ca.pem", AgentHosts: []string{"api.github.com"},
		MappedAddrs: []string{"140.82.112.6", "2606:50c0:8000::154"},
		Canary:      Target{Addrs: []string{"192.168.65.254"}, DNS: 18453, HTTPS: 18443, SSH: 18422},
		HostAddrs:   []string{"192.168.65.254"}, HostPorts: []int{8090},
	}
}

func TestHR121_TheCatalogHasEveryProbeAndControl(t *testing.T) {
	type key struct{ name, role, expect string }
	have := map[key]int{}
	targets := map[string]bool{}
	for _, p := range catalog(config()) {
		have[key{p.name, p.role, p.expect}]++
		if targets[p.name+" "+p.target] {
			t.Errorf("%s %s twice", p.name, p.target)
		}
		targets[p.name+" "+p.target] = true
	}
	for _, name := range []string{
		"dns_docker_resolver", "dns_external", "ipv6", "icmp", "direct_https", "direct_ssh", "ssh_push", "pat_push",
		"metadata", "host_gateway", "docker_socket",
	} {
		if have[key{name, report.RoleProbe, report.Blocked}] == 0 {
			t.Errorf("no %s probe", name)
		}
	}
	for k, n := range map[key]int{
		{"edge_unmapped_refused", report.RoleNegative, report.Blocked}: 2,
		{"edge_mediated", report.RolePositive, report.Reachable}:       1,
		{"edge_reachable", report.RolePositive, report.Reachable}:      1,
		{"dns_resolver_works", report.RolePositive, report.Reachable}:  1,
	} {
		if have[k] != n {
			t.Errorf("%+v: %d, want %d", k, have[k], n)
		}
	}
	for _, target := range []string{
		"dns_docker_resolver 127.0.0.11 api.github.com", "dns_external udp 192.168.65.254:18453", "dns_external tcp 192.168.65.254:18453",
		"direct_https 140.82.112.6:443", "direct_https 192.168.65.254:18443", "direct_ssh 140.82.112.6:22", "direct_ssh 192.168.65.254:18422",
		"ssh_push 140.82.112.6:22", "pat_push direct 192.168.65.254:18443", "ipv6 2606:50c0:8000::154", "icmp echo 140.82.112.6",
		"icmp echo 192.168.65.254", "metadata [fd00:ec2::254]:80", "host_gateway 192.168.65.254:8090", "host_gateway host.docker.internal:8090",
	} {
		if !targets[target] {
			t.Errorf("no probe of %s", target)
		}
	}
}

// TestHR121_ProbesContactNoThirdParty: every address a probe names is the
// canary's, the host's, a mapped host's, this network's bridge, link-local
// metadata or a documentation address (G0 M9 design decision 8).
func TestHR121_ProbesContactNoThirdParty(t *testing.T) {
	c := config()
	allowed := map[string]bool{"127.0.0.11": true, "169.254.169.254": true, "fd00:ec2::254": true, "2001:db8::1": true, bridgeGateway(): true}
	for _, a := range append(append(append([]string{}, c.Canary.Addrs...), c.MappedAddrs...), c.HostAddrs...) {
		allowed[a] = true
	}
	ipRE := regexp.MustCompile(`\[?([0-9a-f:]*:[0-9a-f:]+|\d+\.\d+\.\d+\.\d+)\]?`)
	for _, p := range catalog(c) {
		for _, m := range ipRE.FindAllStringSubmatch(p.target, -1) {
			if a, err := netip.ParseAddr(m[1]); err == nil && !allowed[a.String()] {
				t.Errorf("%s contacts %s", p.name, a)
			}
		}
		for _, name := range []string{"github.com", "example.com", "invalid"} {
			if strings.Contains(p.target, name) && !strings.Contains(p.target, "edge") && !strings.HasPrefix(p.target, "127.0.0.11") && !strings.HasPrefix(p.target, "CONNECT") && !strings.HasPrefix(p.target, "GET http://unmapped") {
				t.Errorf("%s names %s outside the edge: %s", p.name, name, p.target)
			}
		}
	}
}

func TestHR121_TheControlRunAimsOnlyAtTheCanary(t *testing.T) {
	c := config()
	c.Kind = report.KindControl
	ps := catalog(c)
	if len(ps) != 5 {
		t.Fatalf("%d control probes", len(ps))
	}
	for _, p := range ps {
		if p.name != "canary_control" || p.role != report.RolePositive || p.expect != report.Reachable || !strings.Contains(p.target, "192.168.65.254") {
			t.Errorf("control probe %+v", p)
		}
	}
}

// TestHR214_AnEdgeRefusalIsBlocked: a request the edge refused never left
// the sandbox, whatever its status; the gateway's answer is reachable.
func TestHR214_AnEdgeRefusalIsBlocked(t *testing.T) {
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("PC-Refused-By", "edge")
		w.WriteHeader(http.StatusForbidden)
	}))
	defer refused.Close()
	answered := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer answered.Close()
	u, _ := url.Parse(refused.URL)
	if err := viaEdge(u, nil, http.MethodGet, "http://unmapped.invalid/x", nil)(t.Context()); err == nil {
		t.Fatal("an edge refusal was reachable")
	}
	u, _ = url.Parse(answered.URL)
	if err := viaEdge(u, nil, http.MethodGet, "http://payments.example/x", nil)(t.Context()); err != nil {
		t.Fatalf("the gateway's 404 was blocked: %v", err)
	}
}

func TestReadConfigIsStrict(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"format":        `{"format":"v0","kind":"sandbox"}`,
		"kind":          `{"format":"pantherclaw.probe/v1","kind":"agent","key_file":"k","canary":{"addrs":["10.0.0.1"]}}`,
		"no edge":       `{"format":"pantherclaw.probe/v1","kind":"sandbox","key_file":"k","canary":{"addrs":["10.0.0.1"]}}`,
		"canary name":   `{"format":"pantherclaw.probe/v1","kind":"control","key_file":"k","canary":{"addrs":["canary.example"]}}`,
		"unknown field": `{"format":"pantherclaw.probe/v1","kind":"control","key_file":"k","canary":{"addrs":["10.0.0.1"]},"shell":"sh"}`,
	} {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConfig(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProbeRunsOnlyInLinuxContainers(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("on Linux the catalog runs")
	}
	if _, err := Probe(t.Context(), config()); err == nil {
		t.Fatal("the catalog ran outside a Linux container")
	}
}

func TestPlantedTokenCarriesTheMarker(t *testing.T) {
	m := report.Marker("n")
	if !strings.Contains(base64Decode(t, plantedPAT(m)), "ghp_"+m) {
		t.Fatal("the planted token lacks the marker")
	}
}

func base64Decode(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
