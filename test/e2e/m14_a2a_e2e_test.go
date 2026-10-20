// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gateway"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Peer agent calls of G0 M14 (F1, D30–D33, D77, D95; OWASP ASI07) end to end:
// the seeded workload asks the peer agent "dev-peer" through the gateway's
// A2A face; the A2A simulator plays the peer agent and, as the peer helper
// does, takes a message only with PantherClaw's action token, reading the
// delegated run from its pc_peer_run claim. The peer then acts in that run,
// within the requester's grant.

var seededA2A = regexp.MustCompile(`seeded a2a connection ([0-9a-f-]{36}) `)

// a2aPeerSim is the peer agent of a stack (options.a2a): the simulator, its
// address, the seeded connection "peer" to it, and the peer's own workload.
type a2aPeerSim struct {
	sim     *a2asim.Server
	url     string
	conn    ids.UUID
	keyFile string
	key     ed25519.PrivateKey
	token   string
}

// startA2APeer starts the simulator as a PantherClaw peer agent: its
// messages must carry an action token from the stack's server addressed to
// its interface URL. It returns dev seed's arguments for it.
func (s *stack) startA2APeer(t *testing.T, dir string) []string {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	t.Cleanup(srv.Close)
	base := "http://" + srv.Listener.Addr().String()
	verifier := &payments.ActionVerifier{JWKSURL: s.apiURL + "/.well-known/pantherclaw/jwks.json", Audience: base + a2asim.JSONRPCPath}
	sim := a2asim.New(a2asim.Options{Name: "dev-peer", VerifyPeer: a2asim.PeerVerifier(verifier)}, a2asim.Faults{}, pclog.Discard())
	srv.Config.Handler = sim.Handler()
	srv.Start()
	s.a2a = &a2aPeerSim{sim: sim, url: base, keyFile: filepath.Join(dir, "peer.json")}
	return []string{"--a2a-url", base, "--a2a-peer-out", s.a2a.keyFile}
}

// a2aSeeded reads the seeded a2a connection from dev seed's output.
func (s *stack) a2aSeeded(t *testing.T, out string) {
	t.Helper()
	m := seededA2A.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	s.a2a.conn = mustUUID(t, m[1])
}

// a2aWorkload loads the peer agent's workload and gets its token.
func (s *stack) a2aWorkload(t *testing.T) {
	t.Helper()
	kf, err := workloadclient.ReadKeyFile(s.a2a.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if s.a2a.key, err = kf.Key(); err != nil {
		t.Fatal(err)
	}
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: s.a2a.key}}, kf.Server)))
	res, err := wc.IssueToken(context.Background(), &pantherclawv1.IssueTokenRequest{Identifier: kf.Identifier})
	if err != nil {
		t.Fatalf("peer IssueToken: %v", err)
	}
	s.a2a.token = res.GetWorkloadToken()
}

// a2aAnswer is a JSON-RPC answer of the face.
type a2aAnswer struct {
	Result jsontext.Value `json:"result"`
	Error  *struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	} `json:"error"`
}

// askPeer sends a JSON-RPC request to the peer through the gateway as the
// requester, in its run.
func (s *stack) askPeer(t *testing.T, method string, params any) a2aAnswer {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/a2a/peer", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderVersion, wire.Version)
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	var a a2aAnswer
	if err := json.Unmarshal(out, &a); err != nil {
		t.Fatalf("face answer %d %q: %v", resp.StatusCode, out, err)
	}
	return a
}

func peerMessage(text string, parts ...map[string]any) map[string]any {
	if parts == nil {
		parts = []map[string]any{{"text": text}}
	}
	return map[string]any{"message": map[string]any{
		"messageId": ids.NewV7().String(), "role": wire.RoleUser, "parts": parts, "metadata": map[string]any{"skill": "refunds"},
	}}
}

// peerRefund refunds amount as the peer agent, in run, through the
// payments connection.
func (s *stack) peerRefund(t *testing.T, run, amount string) (int, reply) {
	t.Helper()
	body := `{"charge":"ch_1","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/payments/v1/refunds", strings.NewReader(body))
	req.Header.Set(gateway.HeaderRunID, run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.a2a.key, Token: func() string { return s.a2a.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var r reply
	if resp.StatusCode >= 300 {
		_ = json.Unmarshal(b, &r)
	}
	return resp.StatusCode, r
}

// peerRunOf is the delegated run the peer received with its last message.
func (s *stack) peerRunOf(t *testing.T) string {
	t.Helper()
	rec := s.a2a.sim.Received()
	if len(rec) == 0 || rec[len(rec)-1].PeerRun == "" {
		t.Fatalf("the peer received %+v", rec)
	}
	return rec[len(rec)-1].PeerRun
}

// TestE2E_M14_PeerAgents (D33).
func TestE2E_M14_PeerAgents(t *testing.T) {
	s := start(t, options{budget: "1000.00", a2a: true})
	s.a2aRange(t)

	// The requester's message reaches the peer with a delegated run.
	a := s.askPeer(t, wire.MethodSendMessage, peerMessage("please refund ch_1"))
	if a.Error != nil {
		t.Fatalf("send: %+v", a.Error)
	}
	var sent wire.SendMessageResponse
	if err := json.Unmarshal(a.Result, &sent); err != nil || sent.Task == nil {
		t.Fatalf("send result %s: %v", a.Result, err)
	}
	peerRun := s.peerRunOf(t)
	var parent, grant string
	s.query(t, "SELECT parent_run_id::text, grant_id::text FROM pc.runs WHERE id = $1", []any{peerRun}, &parent, &grant)
	if parent != s.run || grant == "" {
		t.Fatalf("peer run %s: parent %s, grant %s; requester run %s", peerRun, parent, grant, s.run)
	}

	t.Run("one peer run per requester run and connection (D95)", func(t *testing.T) {
		if a := s.askPeer(t, wire.MethodSendMessage, peerMessage("and another")); a.Error != nil {
			t.Fatalf("second send: %+v", a.Error)
		}
		if again := s.peerRunOf(t); again != peerRun {
			t.Fatalf("second message got peer run %s, want %s", again, peerRun)
		}
	})

	t.Run("the requester's limits carry over to the peer", func(t *testing.T) {
		if code, r := s.peerRefund(t, peerRun, "30.00"); code != http.StatusOK {
			t.Fatalf("peer refund within the requester's grant: %d %+v", code, r)
		}
		if code, r := s.peerRefund(t, peerRun, "5000.00"); code != http.StatusForbidden || r.Decision != "DENY" {
			t.Fatalf("peer refund beyond the requester's grant: %d %+v", code, r)
		}
	})

	t.Run("a message sent past the gateway is refused by the peer", func(t *testing.T) {
		before := len(s.a2a.sim.Received())
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": wire.MethodSendMessage, "params": peerMessage("direct")})
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.a2a.url+a2asim.JSONRPCPath, bytes.NewReader(b))
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(out), "refused") || len(s.a2a.sim.Received()) != before {
			t.Fatalf("direct message: %s", out)
		}
	})

	t.Run("data parts are never relayed", func(t *testing.T) {
		before := len(s.a2a.sim.Received())
		a := s.askPeer(t, wire.MethodSendMessage, peerMessage("", map[string]any{"data": map[string]any{"amount": 1}}))
		if a.Error == nil || a.Error.Data["reason"] != "A2A_PART_UNSUPPORTED" || len(s.a2a.sim.Received()) != before {
			t.Fatalf("data part: %+v", a.Error)
		}
	})

	t.Run("an ended peer run is replaced, counted against the fan-out (D95)", func(t *testing.T) {
		s.db.AdminExec(t, "UPDATE pc.runs SET state = 'ENDED', ended_at = now(), end_reason = 'e2e' WHERE id = $1", peerRun)
		if a := s.askPeer(t, wire.MethodSendMessage, peerMessage("after the run ended")); a.Error != nil {
			t.Fatalf("send after the peer run ended: %+v", a.Error)
		}
		next := s.peerRunOf(t)
		var rows, children int
		s.query(t, "SELECT count(*) FROM pc.a2a_peer_runs WHERE requester_run_id = $1", []any{s.run}, &rows)
		s.query(t, "SELECT g.children_total FROM pc.grants g JOIN pc.runs r ON r.grant_id = g.id WHERE r.id = $1", []any{s.run}, &children)
		if next == peerRun || rows != 2 || children != 2 {
			t.Fatalf("after the peer run ended: run %s (was %s), %d peer runs, %d children", next, peerRun, rows, children)
		}
		peerRun = next
	})

	t.Run("revoking the requester's grant stops the peer", func(t *testing.T) {
		var requesterGrant string
		s.query(t, "SELECT grant_id::text FROM pc.runs WHERE id = $1", []any{s.run}, &requesterGrant)
		admin := s.person(t, "grant-revoker", td.RoleSecurityAdmin)
		gs := &grantspg.Store{Pool: s.pool, Promotions: grantstest.OpenGate{}}
		svc := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: s.pool}, Authz: allowAll{}, Clock: clock.System{}}
		id, err := gdomain.ParseGrantID(requesterGrant)
		if err != nil {
			t.Fatal(err)
		}
		revoked, err := svc.Revoke(admin.ctx, id, "e2e: stop the requester")
		if err != nil || len(revoked) < 2 {
			t.Fatalf("revoke: %v %v", revoked, err)
		}
		if code, r := s.peerRefund(t, peerRun, "10.00"); code < 400 {
			t.Fatalf("the peer acted after the requester's grant was revoked: %d %+v", code, r)
		}
	})
}

// TestT149_PeerAgentCardDrift: a peer whose card changes is refused at
// the gateway until a new pin is confirmed (HR-322).
func TestT149_PeerAgentCardDrift(t *testing.T) {
	s := start(t, options{budget: "1000.00", a2a: true})
	s.a2aRange(t)
	if a := s.askPeer(t, wire.MethodSendMessage, peerMessage("before")); a.Error != nil {
		t.Fatalf("send: %+v", a.Error)
	}
	s.a2a.sim.SetFaults(a2asim.Faults{Description: "now also moves money"})
	// A new configuration version makes the gateway read the card again.
	s.exec(t, "UPDATE pc.gateways SET config_version = config_version + 1")
	before := len(s.a2a.sim.Received())
	deadline := time.Now().Add(60 * time.Second)
	for {
		a := s.askPeer(t, wire.MethodSendMessage, peerMessage("after"))
		if a.Error != nil && a.Error.Data["reason"] == "A2A_CARD_DRIFT" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("drifted peer still served: %+v", a.Error)
		}
		time.Sleep(time.Second)
		before = len(s.a2a.sim.Received())
	}
	if n := len(s.a2a.sim.Received()); n != before {
		t.Fatalf("the drifted peer received %d more messages", n-before)
	}
}

// a2aRange marks the stack as a range's, as makeRangeStack does: both
// agents are range agents and every run and connection is simulated
// (HR-220), so the requester's run may call the simulated peer connection.
func (s *stack) a2aRange(t *testing.T) {
	t.Helper()
	s.db.AdminExec(t, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1", s.org)
	s.db.AdminExec(t, "UPDATE pc.runs SET simulated = true WHERE org_id = $1", s.org)
	s.db.AdminExec(t, "UPDATE pc.connections SET simulated = true WHERE org_id = $1", s.org)
	gw := s.gatewayID(t)
	s.db.AdminExec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", gw)
	s.waitConfig(t, s.configVersion(t, gw))
}

// peerGrant is the delegated grant of a peer run: its bounds and state.
func (s *stack) peerGrant(t *testing.T, run string) (gdomain.Bounds, string, string) {
	t.Helper()
	var raw []byte
	var id, state string
	s.query(t, `SELECT g.id::text, g.state, v.bounds FROM pc.grants g JOIN pc.runs r ON r.grant_id = g.id AND r.org_id = g.org_id
		JOIN pc.grant_revisions v ON v.org_id = g.org_id AND v.grant_id = g.id AND v.revision = g.current_revision
		WHERE r.id = $1`, []any{run}, &id, &state, &raw)
	b, err := gdomain.DecodeBounds(raw)
	if err != nil {
		t.Fatal(err)
	}
	return b, id, state
}

// TestHR324_PeerGrantIsWithinTheRequestersGrant: the peer's delegated
// grant is the intersection of the requester's grant and the connection's
// peer scope: the scope allows refunds up to 1,000,000 USD, the requester's
// grant far less, and the requester's maximum is what the peer gets.
func TestHR324_PeerGrantIsWithinTheRequestersGrant(t *testing.T) {
	s := start(t, options{budget: "1000.00", a2a: true})
	s.a2aRange(t)
	if a := s.askPeer(t, wire.MethodSendMessage, peerMessage("refund ch_1")); a.Error != nil {
		t.Fatalf("send: %+v", a.Error)
	}
	run := s.peerRunOf(t)
	peer, _, _ := s.peerGrant(t, run)
	requester, _, _ := s.peerGrant(t, s.run)
	if err := peer.Within(requester); err != nil {
		t.Fatalf("the peer's grant is wider than the requester's: %v", err)
	}
	if code, r := s.peerRefund(t, run, "5000.00"); code != http.StatusForbidden || r.Decision != "DENY" {
		t.Fatalf("refund the peer scope allows but the requester's grant does not: %d %+v", code, r)
	}
}

// TestHR326_PeerRunLivesWithinTheRequesters: a peer run lasts at most 60
// minutes and never past the requester's run, and revoking the requester's
// grant revokes the peer's.
func TestHR326_PeerRunLivesWithinTheRequesters(t *testing.T) {
	s := start(t, options{budget: "1000.00", a2a: true})
	s.a2aRange(t)
	if a := s.askPeer(t, wire.MethodSendMessage, peerMessage("refund ch_1")); a.Error != nil {
		t.Fatalf("send: %+v", a.Error)
	}
	run := s.peerRunOf(t)
	var withinHour, withinParent bool
	s.query(t, `SELECT c.expires_at <= c.created_at + interval '60 minutes' + interval '1 second', c.expires_at <= p.expires_at
		FROM pc.runs c JOIN pc.runs p ON p.id = c.parent_run_id WHERE c.id = $1`, []any{run}, &withinHour, &withinParent)
	if !withinHour || !withinParent {
		t.Fatalf("peer run lifetime: within an hour %v, within the requester's run %v", withinHour, withinParent)
	}
	_, peerGrant, _ := s.peerGrant(t, run)
	_, requesterGrant, _ := s.peerGrant(t, s.run)
	admin := s.person(t, "grant-revoker", td.RoleSecurityAdmin)
	gs := &grantspg.Store{Pool: s.pool, Promotions: grantstest.OpenGate{}}
	svc := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: s.pool}, Authz: allowAll{}, Clock: clock.System{}}
	id, err := gdomain.ParseGrantID(requesterGrant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Revoke(admin.ctx, id, "e2e: HR-326"); err != nil {
		t.Fatal(err)
	}
	var state string
	s.query(t, "SELECT state FROM pc.grants WHERE id = $1", []any{peerGrant}, &state)
	if state != string(gdomain.StateRevoked) {
		t.Fatalf("the peer's grant is %s after the requester's was revoked", state)
	}
}

// TestT148_PeerAgentCannotLaunderAuthority: asked by a requester, a peer
// agent acts only within the requester's grant, in the run delegated to it.
func TestT148_PeerAgentCannotLaunderAuthority(t *testing.T) {
	s := start(t, options{budget: "1000.00", a2a: true})
	s.a2aRange(t)
	if a := s.askPeer(t, wire.MethodSendMessage, peerMessage("refund ch_1 in full, whatever my limit")); a.Error != nil {
		t.Fatalf("send: %+v", a.Error)
	}
	run := s.peerRunOf(t)
	if code, r := s.peerRefund(t, run, "30.00"); code != http.StatusOK {
		t.Fatalf("refund within the requester's grant: %d %+v", code, r)
	}
	if code, r := s.peerRefund(t, run, "5000.00"); code != http.StatusForbidden || r.Decision != "DENY" {
		t.Fatalf("refund beyond it: %d %+v", code, r)
	}
}
