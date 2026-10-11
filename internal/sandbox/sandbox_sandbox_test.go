// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package sandbox_test

import (
	"bytes"
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
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sim/canary"
)

// rig is a real sandbox on this host's engine: the edge and probe images
// (as task sandbox:images builds them), a fake gateway that answers every
// request as an unknown route, and the canary.
type rig struct {
	c                                 *docker.Client
	e                                 docker.Engine
	s                                 *sandbox.Sandbox
	session                           string
	probeKey, hostKey                 ed25519.PrivateKey
	dir                               string
	edgeImage, probeImage, agentImage string
	mu                                sync.Mutex
	seen                              []*http.Request
}

func (r *rig) requests() []*http.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*http.Request(nil), r.seen...)
}

// newRig starts a sandbox; agentImage, when set, is the session's agent.
func newRig(t *testing.T, agent bool) *rig {
	t.Helper()
	c, e := dockertest.Client(t)
	r := &rig{c: c, e: e, session: ids.NewV7().String()}
	r.edgeImage = dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile")
	r.probeImage = dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-probe", "deploy/sandbox/probe.Dockerfile")
	if agent {
		r.agentImage = dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/internal/sandbox/testdata/agent", "internal/sandbox/testdata/agent.Dockerfile")
	}
	dir := t.TempDir()
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Clone(context.Background()))
		r.mu.Unlock()
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
	_, r.probeKey, _ = ed25519.GenerateKey(rand.Reader)
	_, r.hostKey, _ = ed25519.GenerateKey(rand.Reader)
	r.dir = dir
	port, _ := strconv.Atoi(gport)
	r.s, err = sandbox.Start(t.Context(), c, e, sandbox.Options{
		Session: r.session, EdgeImage: r.edgeImage, ProbeImage: r.probeImage, AgentImage: r.agentImage,
		GatewayURL: "http://127.0.0.1:" + gport, GatewayAddr: "host.docker.internal:" + gport,
		Hosts: map[string]string{"payments.example": "payments"}, MappedAddrs: []string{"192.0.2.10"},
		Run: ids.NewV7().String(), KeyFile: keyFile, TokenFile: filepath.Join(tokens, "token"),
		ProbeKey: r.probeKey, HostKey: r.hostKey, Canary: cn, CanaryPorts: ports, HostPorts: []int{port}, Dir: dir,
	})
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := r.s.Close(cctx); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestT086_TheSandboxIsClosedAndTheReportsSayWhy: every probe from the
// sandbox network is blocked, the edge refuses an unmapped host and
// reaches the gateway for a mapped one, signed; the control run reaches
// the canary and the probe run does not; and all three reports verify with
// the session's probe key (HR-121, HR-122, HR-213, HR-214, HR-215, T-086).
func TestT086_TheSandboxIsClosedAndTheReportsSayWhy(t *testing.T) {
	r := newRig(t, false)
	n := sandbox.Nonces{Sandbox: nonce(), Control: nonce(), Canary: nonce()}
	ev, err := r.s.Probe(t.Context(), n)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, x := range ev.Results {
		names[x.Name] = true
		t.Logf("%-22s %-16s %-9s %s", x.Name, x.Role, x.Observed, x.Detail)
		if !x.Passed() {
			t.Errorf("%s (%s): expected %s, observed %s: %s", x.Name, x.Role, x.Expect, x.Observed, x.Detail)
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
	// Every probe with a live target on the open network has a passing
	// positive twin under its own name.
	twinned := map[string]bool{}
	for _, x := range ev.Results {
		if x.Role == report.RolePositive && x.Passed() {
			twinned[x.Name] = true
		}
	}
	for _, name := range []string{"dns_docker_resolver", "dns_external", "icmp", "direct_https", "direct_ssh", "ssh_push", "pat_push", "host_gateway", "docker_socket"} {
		if !twinned[name] {
			t.Errorf("no passing twin of %s", name)
		}
	}
	// The sandbox run's report verifies with the probe key and the control
	// run's and the canary's with the host key alone; all carry their
	// nonces and the session's facts. The probe key's file is gone.
	probePub, hostPub := r.probeKey.Public().(ed25519.PublicKey), r.hostKey.Public().(ed25519.PublicKey)
	for kind, tc := range map[string]struct {
		compact, nonce string
		key, other     ed25519.PublicKey
	}{
		report.KindSandbox: {ev.Sandbox, n.Sandbox, probePub, hostPub}, report.KindControl: {ev.Control, n.Control, hostPub, probePub},
		report.KindCanary: {ev.Canary, n.Canary, hostPub, probePub},
	} {
		if _, err := report.Verify(tc.compact, tc.other); err == nil {
			t.Errorf("the %s report verifies with the other key", kind)
		}
		rep, err := report.Verify(tc.compact, tc.key)
		if err != nil {
			t.Fatalf("%s report: %v", kind, err)
		}
		if rep.Kind != kind || rep.Nonce != tc.nonce || rep.Session != r.session || rep.Engine.Runtime != r.e.Runtime() ||
			!rep.Network.Internal || rep.Network.GatewayModeIPv4 != "isolated" || rep.Network.IPv6 || rep.Images.Edge != r.edgeImage ||
			rep.Config.Digest == "" {
			t.Errorf("%s report %+v", kind, rep)
		}
	}
	if keys, _ := filepath.Glob(filepath.Join(r.dir, "*probe-key*")); len(keys) != 0 {
		t.Errorf("the probe key outlived its run: %v", keys)
	}
	can, _ := report.Verify(ev.Canary, hostPub)
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
	var mediated bool
	for _, req := range r.requests() {
		if strings.HasPrefix(req.URL.Path, "/payments/.well-known/pantherclaw-probe/") && req.Header.Get("Authorization") == "PAP workload-token" &&
			req.Header.Get("PAP-Proof") != "" && req.Header.Get("PC-Sandbox-Session") == r.session {
			mediated = true
		}
	}
	if !mediated {
		t.Errorf("the gateway never got the mediated probe: %d requests", len(r.requests()))
	}
}

// TestHR213_TheAgentHasItsWorkspaceAndOnlyTheEdge: the agent runs as its
// own non-root uid with a copy of the workspace, reaches a mapped host only
// through the edge (to the gateway, signed by the edge), cannot connect
// directly, holds no credential, and its work is copied back out.
func TestHR213_TheAgentHasItsWorkspaceAndOnlyTheEdge(t *testing.T) {
	r := newRig(t, true)
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "in.txt"), []byte("question\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := nonce()
	if err := r.s.PrepareAgent(t.Context(), sandbox.Agent{Image: r.agentImage, Args: []string{"payments.example", marker}, Workspace: in}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, err := r.c.Attach(t.Context(), r.s.Agent, nil, &out)
	if err != nil || code != 0 {
		t.Fatalf("agent exited %d, %v:\n%s", code, err, out.String())
	}
	got := out.String()
	t.Log(got)
	for _, want := range []string{"read question <nil>", "write <nil>", "uid 65533", "proxied 404", "direct blocked"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("agent output lacks %q", want)
		}
	}
	if strings.Contains(got, "credential env") {
		t.Errorf("the agent saw a credential:\n%s", got)
	}
	var signed bool
	for _, req := range r.requests() {
		if req.URL.Path == "/payments/agent/"+marker && req.Header.Get("Authorization") == "PAP workload-token" {
			signed = true
		}
	}
	if !signed {
		t.Error("the agent's call never reached the gateway signed by the edge")
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := r.s.CopyOut(t.Context(), dst); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "out.txt")); err != nil || string(b) != "question\nanswered\n" {
		t.Fatalf("copied out %q, %v", b, err)
	}
	if err := r.s.CopyOut(t.Context(), dst); err == nil {
		t.Fatal("copied into a directory that is not empty")
	}
}

func nonce() string {
	return strings.ReplaceAll(ids.NewV7().String(), "-", "")
}
