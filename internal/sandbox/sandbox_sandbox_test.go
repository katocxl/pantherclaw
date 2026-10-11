// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package sandbox_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sim/canary"
)

// TestT086_TheSandboxIsClosedAndTheReportsSayWhy builds a real sandbox:
// the edge and probe images (as task sandbox:images builds them), an
// isolated internal network and an uplink, a fake gateway and the canary on
// this host. Every probe from the sandbox network is blocked, the edge
// refuses an unmapped host and reaches the gateway for a mapped one,
// signed; the control run reaches the canary and the probe run does not;
// and all three reports verify with the session's probe key (HR-121,
// HR-122, HR-213, HR-214, HR-215, T-086).
func TestT086_TheSandboxIsClosedAndTheReportsSayWhy(t *testing.T) {
	c, e := dockertest.Client(t)
	edgeImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile")
	probeImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-probe", "deploy/sandbox/probe.Dockerfile")
	dir := t.TempDir()

	// The gateway: answers every request as an unknown route.
	var mu sync.Mutex
	var seen []*http.Request
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error_class":"CANNOT_AUTHORIZE","error":"unknown_route"}`)
	}))
	t.Cleanup(gw.Close)
	_, gport, _ := net.SplitHostPort(gw.Listener.Addr().String())

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	cn := canary.New(pclog.Discard())
	ports, err := cn.Listen(ctx, "127.0.0.1", canary.Ports{})
	if err != nil {
		t.Fatal(err)
	}

	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "workload.json")
	if err := workloadclient.WriteKeyFile(keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	tokens := filepath.Join(dir, "token")
	if err := os.Mkdir(tokens, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokens, "token"), []byte("workload-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, probeKey, _ := ed25519.GenerateKey(rand.Reader)
	port, _ := strconv.Atoi(gport)
	session := ids.NewV7().String()
	s, err := sandbox.Start(t.Context(), c, e, sandbox.Options{
		Session: session, EdgeImage: edgeImage, ProbeImage: probeImage,
		GatewayURL: "http://127.0.0.1:" + gport, GatewayAddr: "host.docker.internal:" + gport,
		Hosts: map[string]string{"payments.example": "payments"}, MappedAddrs: []string{"192.0.2.10"},
		Run: ids.NewV7().String(), KeyFile: keyFile, TokenFile: filepath.Join(tokens, "token"),
		ProbeKey: probeKey, Canary: cn, CanaryPorts: ports, HostPorts: []int{port}, Dir: dir,
	})
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.Close(cctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	n := sandbox.Nonces{Sandbox: nonce(), Control: nonce(), Canary: nonce()}
	ev, err := s.Probe(t.Context(), n)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range ev.Results {
		names[r.Name] = true
		t.Logf("%-22s %-16s %-9s %s", r.Name, r.Role, r.Observed, r.Detail)
		if !r.Passed() {
			t.Errorf("%s (%s): expected %s, observed %s: %s", r.Name, r.Role, r.Expect, r.Observed, r.Detail)
		}
	}
	for _, want := range []string{
		"dns_docker_resolver", "dns_external", "ipv6", "icmp", "direct_https", "direct_ssh", "ssh_push", "pat_push", "metadata",
		"host_gateway", "docker_socket", "edge_unmapped_refused", "edge_mediated", "external_canary", "canary_control",
	} {
		if !names[want] {
			t.Errorf("no %s result", want)
		}
	}

	// The three reports verify with the session's key, carry their nonces
	// and the session's facts.
	pub := probeKey.Public().(ed25519.PublicKey)
	for kind, tc := range map[string]struct{ compact, nonce string }{
		report.KindSandbox: {ev.Sandbox, n.Sandbox}, report.KindControl: {ev.Control, n.Control}, report.KindCanary: {ev.Canary, n.Canary},
	} {
		r, err := report.Verify(tc.compact, pub)
		if err != nil {
			t.Fatalf("%s report: %v", kind, err)
		}
		if r.Kind != kind || r.Nonce != tc.nonce || r.Session != session || r.Engine.Runtime != e.Runtime() || !r.Network.Internal ||
			r.Network.GatewayModeIPv4 != "isolated" || r.Network.IPv6 || r.Images.Edge != edgeImage || r.Config.Digest == "" {
			t.Errorf("%s report %+v", kind, r)
		}
	}
	can, _ := report.Verify(ev.Canary, pub)
	var control, leaked int
	for _, h := range can.Canary.Hits {
		switch h.Marker {
		case report.Marker(n.Control):
			control++
		case report.Marker(n.Sandbox):
			leaked++
		}
	}
	if control == 0 || leaked != 0 {
		t.Errorf("canary hits: %d of the control, %d of the probe run", control, leaked)
	}

	// edge_mediated reached the gateway's face for the connection, signed.
	mu.Lock()
	defer mu.Unlock()
	var mediated bool
	for _, r := range seen {
		if strings.HasPrefix(r.URL.Path, "/payments/.well-known/pantherclaw-probe/") && r.Header.Get("Authorization") == "PAP workload-token" &&
			r.Header.Get("PAP-Proof") != "" && r.Header.Get("PC-Sandbox-Session") == session {
			mediated = true
		}
	}
	if !mediated {
		t.Errorf("the gateway never got the mediated probe: %d requests", len(seen))
	}
}

func nonce() string {
	return strings.ReplaceAll(ids.NewV7().String(), "-", "")
}
