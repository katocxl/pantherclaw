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

func (a *azAgent) refund(t *testing.T, act ids.UUID, charge, amount string, key ed25519.PrivateKey) azReply {
	t.Helper()
	body := []byte(`{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`)
	if key == nil {
		key = a.s.key
	}
	proof, err := pap.NewProof(key, pap.ProofParams{
		Method: http.MethodPost, URL: a.url + "/v1/refunds", Body: body, Token: a.s.token, Nonce: a.nonce, Now: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, a.url+"/v1/refunds", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "PAP "+a.s.token)
	req.Header.Set("PAP-Proof", proof)
	req.Header.Set("PAP-Run-Id", a.s.run)
	req.Header.Set("PC-Action-Id", act.String())
	req.Header.Set("Idempotency-Key", "agent-"+act.String())
	resp, err := http.DefaultClient.Do(req)
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
	refundableMore(t, s, "ch_az1", "ch_az2", "ch_az3", "ch_az4")
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

	// A forged proof forwards nothing.
	_, thief, _ := ed25519.GenerateKey(rand.Reader)
	if r := agent.refund(t, ids.NewV7(), "ch_az2", "10.00", thief); r.status != http.StatusForbidden || s.sim.Stats().Refunds != 1 {
		t.Fatalf("forged: %+v", r)
	}

	// Held, approved, resubmitted with the same action id.
	held := ids.NewV7()
	r = agent.refund(t, held, "ch_az3", "85.00", nil)
	if r.status != http.StatusForbidden || r.outcome != "hold" || r.body["wait_handle"] == nil || s.sim.Stats().Refunds != 1 {
		t.Fatalf("held: %+v", r)
	}
	s.approve(t, b, key, r.txn)
	if r2 := agent.refund(t, held, "ch_az3", "85.00", nil); r2.status != http.StatusOK || r2.outcome != "allow" || r2.txn != r.txn ||
		s.sim.Stats().Refunds != 2 {
		t.Fatalf("approved resubmission: %+v", r2)
	}
	s.waitSettled(t, "115")

	// A monitor route answers true, observes, and reserves nothing.
	s.db.AdminExec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'payments-refund', 'monitor', 'e2e')
		ON CONFLICT (org_id, connection_id, route) DO UPDATE SET mode = 'monitor'`, s.org, s.conn)
	if r := agent.refund(t, ids.NewV7(), "ch_az4", "60.00", nil); r.status != http.StatusOK || r.outcome != "observe" || s.sim.Stats().Refunds != 3 {
		t.Fatalf("monitor: %+v", r)
	}
	s.waitSettled(t, "115")

	// Batches: deny_on_first_deny stops at the refusal, permit_on_first_permit
	// at the permit, execute_all answers each.
	nameOnly := map[string]any{"subject": map[string]any{"type": "user", "id": "alice"}, "resource": map[string]any{"type": "pantherclaw:http_request", "id": "payments"}, "action": map[string]any{"name": "POST"}}
	for sem, want := range map[string]int{"deny_on_first_deny": 1, "permit_on_first_permit": 2, "execute_all": 2} {
		point.nonce = agent.nonce
		good := point.evaluation(t, azRequest{Method: http.MethodPost, Path: "/v1/refunds", Body: []byte(`{}`), Action: ids.NewV7()})
		st, raw := point.post(t, "/access/v1/evaluations", map[string]any{
			"evaluations": []any{nameOnly, good}, "options": map[string]any{"evaluations_semantic": sem},
		}, "")
		var out struct {
			Evaluations []azAnswer `json:"evaluations"`
		}
		if err := json.Unmarshal(raw, &out, json.RejectUnknownMembers(false)); err != nil || st != http.StatusOK || len(out.Evaluations) != want ||
			out.Evaluations[0].Decision {
			t.Fatalf("%s: %d %s", sem, st, raw)
		}
	}
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
		"-client-id", point.clientID, "-key", keyFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if addr, ok := strings.CutPrefix(sc.Text(), "pep: listening on "); ok {
			go func() { _, _ = io.Copy(io.Discard, stdout) }()
			return "http://" + addr
		}
	}
	t.Fatalf("pep exited before listening: %v", sc.Err())
	return ""
}
