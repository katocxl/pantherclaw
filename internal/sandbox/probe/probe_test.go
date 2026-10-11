// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

func config() Config {
	return Config{
		Format: ConfigFormat, Kind: report.KindSandbox, KeyFile: "/pc/key.json",
		Report: report.Report{Session: "s-1", Nonce: "nonce-0123456789abcdef"},
		Edge:   "pc-edge-1:3128", CAFile: "/pc/ca.pem", AgentHosts: []string{"api.github.com"},
		MappedAddrs: []string{"140.82.112.6", "2606:50c0:8000::154"},
		Canary:      Target{Addrs: []string{"192.168.65.254"}, DNS: 18453, HTTPS: 18443, SSH: 18422},
		HostAddrs:   []string{"192.168.65.254"}, HostPorts: []int{8090}, BridgeGateway: "172.19.0.1",
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
		"ssh_push 140.82.112.6:22", "ssh_push push 192.168.65.254:18422", "pat_push direct 192.168.65.254:18443", "ipv6 an IPv6 address or default route", "ipv6 2606:50c0:8000::154", "icmp echo 140.82.112.6",
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
	allowed := map[string]bool{"127.0.0.11": true, "169.254.169.254": true, "fd00:ec2::254": true, c.BridgeGateway: true}
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

// TestHR121_TheControlRunTwinsEveryProbeWithALiveTarget: on the open
// network each probe with a live target there runs again under its own
// name as a positive control, aimed only at the canary, the host and
// Docker's resolver; ipv6, metadata and docker_socket have no twin.
func TestHR121_TheControlRunTwinsEveryProbeWithALiveTarget(t *testing.T) {
	c := config()
	sandbox := map[string]bool{}
	for _, p := range catalog(c) {
		if p.role == report.RoleProbe {
			sandbox[p.name] = true
		}
	}
	c.Kind, c.KeyFile = report.KindControl, ""
	twinned := map[string]bool{}
	for _, p := range catalog(c) {
		twinned[p.name] = true
		if !sandbox[p.name] || p.role != report.RolePositive || p.expect != report.Reachable ||
			(!strings.Contains(p.target, "192.168.65.254") && !strings.HasPrefix(p.target, "127.0.0.11 ")) {
			t.Errorf("control probe %+v", p)
		}
	}
	for name := range sandbox {
		want := name != "ipv6" && name != "metadata" && name != "docker_socket"
		if twinned[name] != want {
			t.Errorf("%s twinned: %v", name, twinned[name])
		}
	}
}

// TestHR121_OnlySilenceIsBlocked: anything that answered is reachable, only
// silence is blocked, and a probe that could not run is an error.
func TestHR121_OnlySilenceIsBlocked(t *testing.T) {
	op := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", err)}
	}
	for err, want := range map[error]string{
		nil:                                      report.Reachable,
		op(syscall.ECONNREFUSED):                 report.Reachable,
		op(syscall.ECONNRESET):                   report.Reachable,
		op(syscall.ENETUNREACH):                  report.Blocked,
		op(syscall.EHOSTUNREACH):                 report.Blocked,
		op(syscall.EADDRNOTAVAIL):                report.Blocked,
		&net.DNSError{IsNotFound: true}:          report.Blocked,
		&net.DNSError{IsTimeout: true}:           report.Blocked,
		&net.DNSError{Err: "server misbehaving"}: report.Blocked,
		context.DeadlineExceeded:                 report.Blocked,
		closed{"refused by the edge"}:            report.Blocked,
		failed{errors.New("no ICMP socket")}:     report.Error,
		op(syscall.EACCES):                       report.Error,
		errors.New("something else"):             report.Error,
	} {
		if got := observe(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
}

// TestHR121_AnAnswerIsReachableAndSilenceBlocked: a listener that resets
// is reachable on Linux, where the probe runs; a DNS server that answers
// anything is reachable and one that never answers is blocked.
func TestHR121_AnAnswerIsReachableAndSilenceBlocked(t *testing.T) {
	answering, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = answering.Close() }()
	go func() {
		b := make([]byte, 512)
		for {
			n, from, err := answering.ReadFrom(b)
			if err != nil {
				return
			}
			b[2] |= 0x80 // a response
			b[3] = 3     // NXDOMAIN
			_, _ = answering.WriteTo(b[:n], from)
		}
	}()
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()
	marker := report.Marker("n")
	if got := observe(answers(answering.LocalAddr().String(), "udp", marker)(t.Context())); got != report.Reachable {
		t.Errorf("an NXDOMAIN answer: %s", got)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	if got := observe(answers(silent.LocalAddr().String(), "udp", marker)(ctx)); got != report.Blocked {
		t.Errorf("no answer: %s", got)
	}
	if runtime.GOOS != "linux" {
		return
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	if got := observe(dialTCP(t.Context(), "tcp", addr)); got != report.Reachable {
		t.Errorf("a reset: %s", got)
	}
}

// TestHR214_AnEdgeRefusalIsBlocked: a request the edge refused never left
// the sandbox, whatever its status, a refused CONNECT included; the
// gateway's answer is reachable, and an edge that cannot be reached is an
// error.
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
	for _, target := range []string{"http://unmapped.invalid/x", "https://unmapped.invalid/x"} {
		if got := observe(viaEdge(u, nil, http.MethodGet, target, nil)(t.Context())); got != report.Blocked {
			t.Errorf("an edge refusal of %s: %s", target, got)
		}
	}
	u, _ = url.Parse(answered.URL)
	if got := observe(viaEdge(u, nil, http.MethodGet, "http://payments.example/x", nil)(t.Context())); got != report.Reachable {
		t.Errorf("the gateway's 404: %s", got)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	u, _ = url.Parse(gone.URL)
	gone.Close()
	if got := observe(viaEdge(u, nil, http.MethodGet, "http://payments.example/x", nil)(t.Context())); got != report.Error {
		t.Errorf("an unreachable edge: %s", got)
	}
}

func TestReadConfigIsStrict(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"format":         `{"format":"v0","kind":"sandbox"}`,
		"kind":           `{"format":"pantherclaw.probe/v1","kind":"agent","key_file":"k","canary":{"addrs":["10.0.0.1"]}}`,
		"no edge":        `{"format":"pantherclaw.probe/v1","kind":"sandbox","key_file":"k","canary":{"addrs":["10.0.0.1"]}}`,
		"canary name":    `{"format":"pantherclaw.probe/v1","kind":"control","canary":{"addrs":["canary.example"]}}`,
		"control key":    `{"format":"pantherclaw.probe/v1","kind":"control","key_file":"k","canary":{"addrs":["10.0.0.1"]}}`,
		"sandbox no key": `{"format":"pantherclaw.probe/v1","kind":"sandbox","edge":"e:1","ca_file":"c","agent_hosts":["a.example"],"canary":{"addrs":["10.0.0.1"]}}`,
		"unknown field":  `{"format":"pantherclaw.probe/v1","kind":"control","canary":{"addrs":["10.0.0.1"]},"shell":"sh"}`,
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

// TestHR121_AnIsolatedNetworkHasNoBridgeToProbe: in isolated gateway mode
// the network has no gateway address, and its first address may be a
// container's, so no host probe aims there; with a gateway, they do.
func TestHR121_AnIsolatedNetworkHasNoBridgeToProbe(t *testing.T) {
	c := config()
	var bridged int
	for _, p := range catalog(c) {
		if strings.HasPrefix(p.target, "172.19.0.1:") {
			bridged++
		}
	}
	if bridged == 0 {
		t.Fatal("no probe of the bridge gateway")
	}
	c.BridgeGateway = ""
	for _, p := range catalog(c) {
		if strings.Contains(p.target, "172.19.0.1") {
			t.Errorf("%s aims at %s", p.name, p.target)
		}
	}
}
