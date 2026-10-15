// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package gateway

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/connectors"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

const connectorID = "01920000-0000-7000-8000-0000000000d9"

// connectorRig is a gateway whose connector connection runs the MCP
// simulator over stdio, in its hardened container, behind an edge of its
// own: its create_refund posts the refund to the payments API, the
// gateway's payments connection, through that edge. With misbehave, the
// simulator sends more than the call by the refund's charge
// (mcpsim.ChargeInflate and the others).
type connectorRig struct {
	*harness
	c      *docker.Client
	listen string
	// log is the supervisor's log: its egress refusals.
	log *syncBuffer
}

// freePorts are the ports freeAddr has handed out in this test binary.
var freePorts sync.Map

// freeAddr returns a loopback address nothing listens on, for a listener
// the test opens later. Its port comes from below every ephemeral range
// (Linux 32768–60999, Windows and macOS 49152–65535), so a listener opened
// on port 0 in the meantime is never given the same port. No port is
// handed out twice.
func freeAddr(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	for range 1000 {
		port := 20000 + rand.IntN(12000)
		if _, taken := freePorts.LoadOrStore(port, true); taken {
			continue
		}
		ln, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		return addr
	}
	t.Fatal("no free loopback port below the ephemeral range")
	return ""
}

func startConnector(t *testing.T, misbehave bool) *connectorRig {
	t.Helper()
	c, e := dockertest.Client(t)
	simImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-sim", "internal/gateway/connectors/testdata/sim.Dockerfile")
	edgeImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile")
	listen := freeAddr(t)
	_, port, _ := net.SplitHostPort(listen)

	// The connector's package dispatches refunds to the simulator's tools,
	// pinned to the digests of the definitions it lists.
	tools := mcpsim.New(mcpsim.Faults{}).Tools()
	create, err := upstream.ToolDigest(tools[0])
	if err != nil {
		t.Fatal(err)
	}
	connector, err := compile(t, "", func(raw []byte) []byte {
		for _, r := range [][2]string{
			{
				"    dispatch:\n      http:\n        method: POST\n        path: /v1/refunds\n        body:\n",
				"    dispatch:\n      mcp:\n        tool: create_refund\n        upstream_digest: " + create + "\n        arguments:\n",
			},
			{"        idempotency_header: Idempotency-Key\n", ""},
		} {
			if bytes.Count(raw, []byte(r[0])) != 1 {
				t.Fatalf("mock payments package: %q not found once", r[0])
			}
			raw = bytes.Replace(raw, []byte(r[0]), []byte(r[1]), 1)
		}
		return raw
	})
	if err != nil {
		t.Fatal(err)
	}
	command := []string{"/pantherclaw-sim", "mcp", "--stdio", "--upstream", "https://payments.test"}
	if misbehave {
		command = append(command, "--misbehave")
	}
	connector.GatewayConnection = &pb.GatewayConnection{
		Id: connectorID, Name: "connector", Kind: "mcp_container", Package: "pc.mock-payments", PackageVersion: "1.0.0",
		DestinationClass: "internal", AccessMode: "none", DefaultMode: "enforce", MaxResponseBytes: 1 << 20, TimeoutMs: 30000,
		State: "ACTIVE", Revision: 1,
		Connector: &pb.ConnectorSpec{
			Image: simImage, Command: command, EgressConnectionId: connID, Revision: 1, CredentialPlaceholders: []string{"PAYMENTS_TOKEN"},
		},
	}
	connector.Modes = map[string]string{}

	log := &syncBuffer{}
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) {
		// The connector names the payments API by an agent host: the edge
		// maps names only, never the base URL's IP literal.
		h.conn.AgentHosts = []string{"payments.test"}
		h.extra = []*control.Connection{connector}
		h.connectors = func(conf connectors.Configuration) *connectors.Supervisor {
			sup, err := connectors.New(t.Context(), c, connectors.Config{
				Enabled: true, EdgeImage: edgeImage, EgressListen: listen, EgressAddr: "host.docker.internal:" + port,
			}, conf, pclog.New(log, pclog.Options{}))
			if err != nil {
				t.Fatal(err)
			}
			return sup
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(2 * time.Minute):
			t.Error("the supervisor did not stop")
		}
	})
	go func() {
		defer close(stopped)
		_ = h.sup.Run(ctx)
	}()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if _, err := h.sup.Client(connectorID, 1); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the connector did not start: %v", err)
		}
		time.Sleep(time.Second)
	}
	return &connectorRig{harness: h, c: c, listen: listen, log: log}
}

// refund calls the connector's create_refund for 30.00 on charge.
func (r *connectorRig) refund(t *testing.T, charge string) mcpReply {
	t.Helper()
	args := `"name":"create_refund","arguments":{"charge":"` + charge + `","amount":"30.00","currency":"USD","reason":"duplicate"}`
	reply := r.mcpCall(t, http.MethodPost, "/mcp/connector", jsonRPC("tools/call", args), map[string]string{"Mcp-Name": "create_refund"})
	if reply.code != http.StatusOK || len(reply.body.Result.Content) != 1 {
		t.Fatalf("tools/call on %s = %d %+v %+v", charge, reply.code, reply.body.Error, reply.body.Result)
	}
	return reply
}

// TestE2E_M9_ConnectorOverStdio: an agent's call to a connector (the MCP
// simulator over stdio, in its hardened container) reaches the payments
// API only through the gateway. The connector's request goes out only
// during the call, only as the authorized action, once; the gateway
// rebuilds it, places the payments credential (which the connector never
// sees, nor gets back) and sends it with the call's idempotency key. A
// connector that inflates the amount or sends the refund twice gets the
// gateway's refusal, and the kill switch engaged mid-call stops its
// request (G0 M9 design decisions 6 and 18, as amended; HR-085, HR-086).
func TestE2E_M9_ConnectorOverStdio(t *testing.T) {
	r := startConnector(t, true)

	r.target.echo = "Authorization"
	res := r.refund(t, "ch_1").body.Result
	if res.IsError || !strings.Contains(res.Content[0].Text, "[REDACTED]") || strings.Contains(res.Content[0].Text, testSecret) {
		t.Fatalf("the connector got %+v", res)
	}
	if r.target.calls() != 1 {
		t.Fatalf("the target got %d requests, want the call's one", r.target.calls())
	}
	body, hdr := r.target.req(0)
	if body != outbound || hdr.Get("Authorization") != "Bearer "+testSecret || !strings.HasPrefix(hdr.Get("Idempotency-Key"), "pc-") {
		t.Fatalf("target got %s, Authorization %q, Idempotency-Key %q", body, hdr.Get("Authorization"), hdr.Get("Idempotency-Key"))
	}
	r.target.echo = ""

	// A 5000.00 refund during a call authorized for 30.00 is refused.
	if res := r.refund(t, mcpsim.ChargeInflate).body.Result; !res.IsError || !strings.Contains(res.Content[0].Text, "outside_the_call") ||
		r.target.calls() != 1 {
		t.Fatalf("an inflated refund: %+v, target %d", res, r.target.calls())
	}
	// The authorized refund goes out once; the same refund again is refused.
	if res := r.refund(t, mcpsim.ChargeTwice).body.Result; !res.IsError || !strings.Contains(res.Content[0].Text, "repeated_write") ||
		r.target.calls() != 2 {
		t.Fatalf("a refund sent twice: %+v, target %d", res, r.target.calls())
	}
	if body, _ := r.target.req(1); !strings.Contains(body, `"charge":"ch_twice"`) {
		t.Fatalf("target got %s", body)
	}

	// The kill switch engaged after the call left for the connector stops
	// the connector's request: the containment checks of a call are counted
	// on one that goes through, then the switch is set past the gateway's
	// own checks of the next one.
	r.containment.mu.Lock()
	before := r.containment.checks
	r.containment.mu.Unlock()
	r.refund(t, "ch_2")
	r.containment.mu.Lock()
	perCall := r.containment.checks - before
	r.containment.killAt = r.containment.checks + perCall - 1 // the egress's own two checks come last
	r.containment.mu.Unlock()
	if r.target.calls() != 3 || perCall < 3 {
		t.Fatalf("target %d, %d checks per call", r.target.calls(), perCall)
	}
	if res := r.refund(t, "ch_3").body.Result; !res.IsError || !strings.Contains(res.Content[0].Text, "contained") || r.target.calls() != 3 {
		t.Fatalf("under the kill switch: %+v, target %d", res, r.target.calls())
	}
	if n := r.refusals("contained"); n != 1 {
		t.Fatalf("the gateway logged %d contained refusals of the connector's egress, want 1", n)
	}
}

// TestT088_AConnectorCannotBreakOutOrTakeACredential: a connector gets no
// Docker socket, host environment, host network or credential (its
// placeholder only, and the edge's CA); the binding token is the edge's
// alone; and a connector that reuses the call to refund another charge,
// or sends its refund again after answering, is refused by the gateway,
// as is any request without the binding (T-088; HR-085, HR-086, HR-216).
func TestT088_AConnectorCannotBreakOutOrTakeACredential(t *testing.T) {
	r := startConnector(t, true)

	short := strings.ReplaceAll(connectorID, "-", "")[16:]
	for _, name := range []string{"pc-conn-" + short, "pc-cedge-" + short} {
		info, err := r.c.InspectContainer(t.Context(), name)
		if err != nil {
			t.Fatal(err)
		}
		hc := info.HostConfig
		if hc.Privileged || hc.NetworkMode == "host" || hc.PidMode == "host" || hc.IpcMode == "host" || hc.UTSMode == "host" ||
			!hc.ReadonlyRootfs || !slices.Contains(hc.CapDrop, "ALL") {
			t.Errorf("%s: host config %+v", name, hc)
		}
		for _, m := range hc.Mounts {
			if strings.Contains(m.Source, "docker.sock") || strings.HasPrefix(m.Target, "/var/run") || !m.ReadOnly {
				t.Errorf("%s: mount %+v", name, m)
			}
		}
		for _, v := range info.Config.Env {
			if strings.Contains(v, testSecret) {
				t.Errorf("%s: the credential is in its environment", name)
			}
			k, _, _ := strings.Cut(v, "=")
			if host, ok := os.LookupEnv(k); ok && host != "" && v == k+"="+host && k != "PATH" {
				t.Errorf("%s: the host's %s is in its environment", name, k)
			}
		}
		if name == "pc-conn-"+short {
			if !slices.Contains(info.Config.Env, "PAYMENTS_TOKEN="+connectors.Placeholder) || len(hc.Mounts) != 1 ||
				hc.Mounts[0].Target != "/pc/ca/ca.pem" {
				t.Errorf("the connector's environment %q, mounts %+v", info.Config.Env, hc.Mounts)
			}
		}
	}

	// The connector refunds the call's charge, then another one: the
	// second is refused.
	if res := r.refund(t, mcpsim.ChargeOther).body.Result; !res.IsError || !strings.Contains(res.Content[0].Text, "outside_the_call") {
		t.Fatalf("a refund of another charge: %+v", res)
	}
	if r.target.calls() != 1 {
		t.Fatalf("the target got %d requests", r.target.calls())
	}
	if body, _ := r.target.req(0); !strings.Contains(body, `"charge":"ch_other"`) {
		t.Fatalf("target got %s", body)
	}
	// The connector answers, then sends its refund again: outside the
	// call, it is refused.
	if res := r.refund(t, mcpsim.ChargeLate).body.Result; res.IsError || r.target.calls() != 2 {
		t.Fatalf("the late connector's call: %+v, target %d", res, r.target.calls())
	}
	// The late request must be seen and refused, not merely absent.
	for deadline := time.Now().Add(mcpsim.LateAfter + 10*time.Second); r.refusals("no_call_in_flight") == 0 && time.Now().Before(deadline); {
		time.Sleep(200 * time.Millisecond)
	}
	if n := r.refusals("no_call_in_flight"); n != 1 || r.target.calls() != 2 {
		t.Fatalf("the refund sent after the call: %d no_call_in_flight refusals, target %d", n, r.target.calls())
	}
	// Nothing reaches the egress listener without the edge's binding.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+r.listen+edge.EgressPath,
		strings.NewReader(`{"connection":"payments","method":"POST","path":"/v1/refunds"}`))
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden || res.Header.Get(edge.HeaderRefusedBy) != "gateway" || r.target.calls() != 2 {
		t.Fatalf("without a binding: %d", res.StatusCode)
	}
}

// syncBuffer is a log the supervisor's goroutines write to while the test
// reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// refusals counts the egress refusals the supervisor logged with code.
func (r *connectorRig) refusals(code string) int {
	r.log.mu.Lock()
	defer r.log.mu.Unlock()
	n := 0
	for line := range strings.Lines(r.log.b.String()) {
		if strings.Contains(line, `"gateway.connector_egress_refused"`) && strings.Contains(line, `"code":"`+code+`"`) {
			n++
		}
	}
	return n
}
