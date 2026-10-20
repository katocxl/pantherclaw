// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// azAgent is the seeded workload calling through the reference
// enforcement point: it signs each request for the URL it calls and keeps
// the nonce the point passes on.
type azAgent struct {
	s     *stack
	url   string
	nonce string
}

type azReply struct {
	status  int
	outcome string
	txn     string
	body    map[string]any
}

// azCall is how one refund is signed.
type azCall struct {
	key ed25519.PrivateKey // nil: the agent's own
	// proofPath signs the proof for another path; noProof sends none.
	proofPath string
	noProof   bool
}

// signed is a signed refund request, sent again verbatim for a replay.
type signed struct {
	url    string
	header http.Header
	body   []byte
}

func (a *azAgent) sign(t *testing.T, act ids.UUID, charge, amount string, c azCall) signed {
	t.Helper()
	body := []byte(`{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`)
	key := c.key
	if key == nil {
		key = a.s.key
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Authorization", "PAP "+a.s.token)
	h.Set("PAP-Run-Id", a.s.run)
	h.Set("PC-Action-Id", act.String())
	h.Set("Idempotency-Key", "agent-"+act.String())
	if !c.noProof {
		path := "/v1/refunds"
		if c.proofPath != "" {
			path = c.proofPath
		}
		proof, err := pap.NewProof(key, pap.ProofParams{
			Method: http.MethodPost, URL: a.url + path, Body: body, Token: a.s.token, Nonce: a.nonce, Now: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		h.Set("PAP-Proof", proof)
	}
	return signed{url: a.url + "/v1/refunds", header: h, body: body}
}

func (a *azAgent) send(t *testing.T, s signed) azReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url, bytes.NewReader(s.body))
	req.Header = s.header.Clone()
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if n := resp.Header.Get("PAP-Nonce"); n != "" {
		a.nonce = n
	}
	raw, _ := io.ReadAll(resp.Body)
	r := azReply{status: resp.StatusCode, outcome: resp.Header.Get("PC-Outcome"), txn: resp.Header.Get("PC-Transaction-Id")}
	_ = json.Unmarshal(raw, &r.body)
	return r
}

func (a *azAgent) refund(t *testing.T, act ids.UUID, charge, amount string, key ed25519.PrivateKey) azReply {
	t.Helper()
	return a.send(t, a.sign(t, act, charge, amount, azCall{key: key}))
}

func code(r azReply) string { s, _ := r.body["code"].(string); return s }

// TestE2E_M14_AuthZEN: the reference enforcement point in front of the
// payments simulator on an agent_held connection (G0 M14 D26-D29). An
// allowed refund is decided, committed DELEGATED and spent, then forwarded
// once; a forged proof forwards nothing; a held refund is refused until a
// person approves it and the agent resubmits the same action; a monitor
// route answers true and observes; batches honour their semantics.
func TestE2E_M14_AuthZEN(t *testing.T) {
	s, _, b, key := approvalStack(t)
	point := authzenPoint(t, s, "agent_held", s.simURL)
	pepURL := runPEP(t, s, point)
	s.db.AdminExec(t, "UPDATE pc.connections SET base_url = $3 WHERE org_id = $1 AND id = $2", s.org, s.conn, pepURL)
	point.base = pepURL
	refundableMore(t, s, "ch_az1", "ch_az2", "ch_az3", "ch_az4", "ch_az5", "ch_az6", "ch_az7", "ch_az8")
	agent := &azAgent{s: s, url: pepURL, nonce: point.liveNonce(t)}

	// Allowed: decided, committed DELEGATED, spent and forwarded once.
	r := agent.refund(t, ids.NewV7(), "ch_az1", "30.00", nil)
	if r.status != http.StatusOK || r.outcome != "allow" || r.txn == "" || s.sim.Stats().Refunds != 1 {
		t.Fatalf("allowed: %+v, %d refunds", r, s.sim.Stats().Refunds)
	}
	if v := s.row(t, `SELECT t.decided_via || ' ' || t.channel || ' ' || a.outcome FROM pc.transactions t
		JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
		JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
		WHERE t.org_id = $1 AND t.id = $2`, s.org, r.txn); v != "authzen authzen delegated" {
		t.Fatalf("recorded: %q", v)
	}
	s.waitSettled(t, "30")

	// Through the PEP, a forged, missing, other-URL or replayed proof
	// forwards nothing and spends nothing.
	_, thief, _ := ed25519.GenerateKey(rand.Reader)
	refused := func(name string, r azReply, want string) {
		t.Helper()
		if r.status != http.StatusForbidden || code(r) != want || s.sim.Stats().Refunds != 1 {
			t.Fatalf("%s: %+v, %d refunds", name, r, s.sim.Stats().Refunds)
		}
	}
	refused("forged", agent.send(t, agent.sign(t, ids.NewV7(), "ch_az2", "10.00", azCall{key: thief})), "IDENTITY_UNVERIFIED")
	refused("missing", agent.send(t, agent.sign(t, ids.NewV7(), "ch_az2", "10.00", azCall{noProof: true})), "PAP_CREDENTIALS_REQUIRED")
	refused("another URL", agent.send(t, agent.sign(t, ids.NewV7(), "ch_az2", "10.00", azCall{proofPath: "/v1/charges"})), "IDENTITY_UNVERIFIED")
	once := agent.sign(t, ids.NewV7(), "ch_az5", "5.00", azCall{})
	if r := agent.send(t, once); r.status != http.StatusOK || s.sim.Stats().Refunds != 2 {
		t.Fatalf("before the replay: %+v", r)
	}
	if r := agent.send(t, once); r.status != http.StatusForbidden || code(r) != "IDENTITY_UNVERIFIED" || s.sim.Stats().Refunds != 2 {
		t.Fatalf("replayed: %+v", r)
	}
	s.waitSettled(t, "35")

	// Held, approved, resubmitted with the same action id.
	held := ids.NewV7()
	r = agent.refund(t, held, "ch_az3", "85.00", nil)
	if r.status != http.StatusForbidden || r.outcome != "hold" || r.body["wait_handle"] == nil || s.sim.Stats().Refunds != 2 {
		t.Fatalf("held: %+v", r)
	}
	s.approve(t, b, key, r.txn)
	if r2 := agent.refund(t, held, "ch_az3", "85.00", nil); r2.status != http.StatusOK || r2.outcome != "allow" || r2.txn != r.txn ||
		s.sim.Stats().Refunds != 3 {
		t.Fatalf("approved resubmission: %+v", r2)
	}
	s.waitSettled(t, "120")

	// Batches: deny_on_first_deny stops at the refusal, permit_on_first_permit
	// at the permit, execute_all answers each; each allowed refund in them is
	// committed DELEGATED and spent exactly once.
	nameOnly := map[string]any{"subject": map[string]any{"type": "user", "id": "alice"}, "resource": map[string]any{"type": "pantherclaw:http_request", "id": "payments"}, "action": map[string]any{"name": "POST"}}
	delegated := func() string {
		return s.row(t, "SELECT count(*) FROM pc.execution_attempts WHERE org_id = $1 AND outcome = 'delegated'", s.org)
	}
	for _, tc := range []struct {
		sem    string
		charge string
		first  bool // the permit comes first
		want   []bool
	}{
		{"deny_on_first_deny", "ch_az6", false, []bool{false}},
		{"permit_on_first_permit", "ch_az7", true, []bool{true}},
		{"execute_all", "ch_az8", true, []bool{true, false}},
	} {
		point.nonce = agent.nonce
		good := point.evaluation(t, azRequest{
			Method: http.MethodPost, Path: "/v1/refunds", Action: ids.NewV7(),
			Body: []byte(`{"charge":"` + tc.charge + `","amount":"5.00","currency":"USD","reason":"duplicate"}`),
		})
		evs := []any{nameOnly, good}
		if tc.first {
			evs = []any{good, nameOnly}
		}
		before := delegated()
		st, raw := point.post(t, "/access/v1/evaluations", map[string]any{"evaluations": evs, "options": map[string]any{"evaluations_semantic": tc.sem}}, "")
		var out struct {
			Evaluations []azAnswer `json:"evaluations"`
		}
		if err := json.Unmarshal(raw, &out, json.RejectUnknownMembers(false)); err != nil || st != http.StatusOK || len(out.Evaluations) != len(tc.want) {
			t.Fatalf("%s: %d %s", tc.sem, st, raw)
		}
		for i, w := range tc.want {
			if out.Evaluations[i].Decision != w {
				t.Fatalf("%s: evaluation %d: %s", tc.sem, i, raw)
			}
			if n := out.Evaluations[i].Context.PantherClaw.Nonce; n != "" {
				agent.nonce = n
			}
		}
		wantDelegated := map[bool]int{true: 1, false: 0}[tc.first]
		if got := delegated(); mustAtoi(t, got)-mustAtoi(t, before) != wantDelegated {
			t.Fatalf("%s: delegated %s → %s", tc.sem, before, got)
		}
	}
	s.waitSettled(t, "130")

	// A monitor route answers true, observes, and reserves nothing.
	s.db.AdminExec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'payments-refund', 'monitor', 'e2e')
		ON CONFLICT (org_id, connection_id, route) DO UPDATE SET mode = 'monitor'`, s.org, s.conn)
	if r := agent.refund(t, ids.NewV7(), "ch_az4", "60.00", nil); r.status != http.StatusOK || r.outcome != "observe" || s.sim.Stats().Refunds != 4 {
		t.Fatalf("monitor: %+v", r)
	}
	s.waitSettled(t, "130")
}

// runPEP builds the reference enforcement point (sdk/go/pep/cmd/pep, its
// own module) and runs it on 127.0.0.1 in front of the payments
// simulator, as point's service account; it returns the URL agents call
// once the command says it listens (D83).
func runPEP(t *testing.T, s *stack, point *azPoint) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "pep")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "-C", "../../sdk/go", "build", "-o", bin, "./pep/cmd/pep").CombinedOutput(); err != nil {
		t.Fatalf("build pep: %v %s", err, out)
	}
	der, err := x509.MarshalPKCS8PrivateKey(point.priv)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "pep-key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-listen", "127.0.0.1:0", "-upstream", s.simURL, "-server", s.apiURL, "-connection", "payments",
		"-client-id", point.clientID, "-key", keyFile, "-forward-header", "Idempotency-Key")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if addr, ok := strings.CutPrefix(sc.Text(), "pep: listening on "); ok {
				ready <- addr
				_, _ = io.Copy(io.Discard, stdout)
				return
			}
		}
		close(ready)
	}()
	deadline := time.NewTimer(time.Minute)
	defer deadline.Stop()
	select {
	case addr, ok := <-ready:
		if !ok {
			t.Fatal("pep exited before listening")
		}
		return "http://" + addr
	case <-deadline.C:
		_ = cmd.Process.Kill()
		t.Fatal("pep did not listen within a minute")
	}
	return ""
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
