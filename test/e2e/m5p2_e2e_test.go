// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/notifications/smtptest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/server"
)

// withPeople serves the API at http://localhost:<port>, where security keys
// work, with the OIDC provider p and, with relay, email; it returns the
// public URL.
func withPeople(t *testing.T, cfg map[string]any, dir, apiAddr string, p idp, relay *smtptest.Server) string {
	t.Helper()
	_, port, _ := net.SplitHostPort(apiAddr)
	public := "http://localhost:" + port
	cfg["auth"] = map[string]any{
		"public_url": public,
		"oidc_providers": []map[string]any{{
			"name": "test", "issuer": p.issuer, "client_id": p.clientID, "allow_insecure_loopback": true,
			"client_secret_file": writeFile(t, dir, "idp-secret", []byte(p.secret)),
		}},
	}
	if relay != nil {
		host, rport, _ := net.SplitHostPort(relay.Addr)
		n, _ := strconv.Atoi(rport)
		cfg["notifications"] = map[string]any{
			"concurrency": 2, "smtp": map[string]any{"host": host, "port": n, "tls": "none", "from": "pantherclaw@example.test"},
		}
	}
	return public
}

var approvalLink = regexp.MustCompile(`(http://localhost:\d+)(/approvals/[0-9a-f-]{36}\?org=[0-9a-f-]{36})`)

// approver makes bob an Approver whose account, role and key are a month
// old, so the cooldowns of decision 5 are met, and returns his browser
// (signed in) and key. alice is the org's administrator.
func approver(t *testing.T, s *stack, people *m2Stack) (*user, *browser, *webauthntest.Authenticator) {
	t.Helper()
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", s.serverCfg, "--org", org}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	code, invite, errs := alice.pclaw(t, "invite", "create", "--email", "bob@example.test", "--role", "approver")
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite bob: %d %s %s", code, invite, errs)
	}
	bob := people.user(t, "bob", "bob@example.test")
	bob.login(t, org, pciToken.FindStringSubmatch(invite)[1])
	b := newBrowser(people)
	b.signIn(t, org, "bob", "bob@example.test", true)
	key, err := webauthntest.New(s.apiURL, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	code, body := b.post(t, "/account/keys/registration-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("registration options: %d %v", code, body)
	}
	resp, err := key.Register(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, body = b.post(t, "/account/keys", map[string]any{"ceremony": body["ceremony"], "name": "Desk key", "response": jsontext.Value(resp)}); code != http.StatusOK {
		t.Fatalf("add key: %d %v", code, body)
	}
	for _, q := range []string{
		`UPDATE pc.users SET created_at = now() - interval '30 days' WHERE org_id = $1 AND subject = 'bob'`,
		`UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1
			AND user_id = (SELECT id FROM pc.users WHERE org_id = $1 AND subject = 'bob')`,
		`UPDATE pc.webauthn_credentials SET created_at = now() - interval '30 days' WHERE org_id = $1
			AND user_id = (SELECT id FROM pc.users WHERE org_id = $1 AND subject = 'bob')`,
	} {
		s.db.AdminExec(t, q, s.org)
	}
	return alice, b, key
}

// approveOnPage opens the link and approves with the key, as the page's
// script does.
func approveOnPage(t *testing.T, b *browser, key *webauthntest.Authenticator, path string) string {
	t.Helper()
	if code, page := b.page(t, path); code != http.StatusOK || !strings.Contains(page, "payments.refund.create") {
		t.Fatalf("approval page: %d", code)
	}
	base, _, _ := strings.Cut(path, "?")
	code, body := b.post(t, base+"/approve-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("approve options: %d %v", code, body)
	}
	resp, err := key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	code, body = b.post(t, base+"/approve", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)})
	if code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, body)
	}
	return string(body["state"])
}

// waitState long-polls the handle as the workload.
func (s *stack) waitState(t *testing.T, handle string, known pantherclawv1.WaitState) *pantherclawv1.WaitInfo {
	t.Helper()
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 40 * time.Second, Transport: &workloadclient.Transport{Key: s.key, Token: func() string { return s.token }},
	}, s.apiURL)))
	res, err := wc.Wait(context.Background(), &pantherclawv1.WaitRequest{RunId: s.run, Handle: handle, KnownState: known, TimeoutSeconds: 30})
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	return res.GetWait()
}

// streamState reads the first state event of the handle's SSE stream.
func (s *stack) streamState(t *testing.T, handle string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, s.apiURL+"/v1/wait/"+handle, nil)
	c := &http.Client{Timeout: 20 * time.Second, Transport: &workloadclient.Transport{Key: s.key, Token: func() string { return s.token }}}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("wait stream: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	sc := bufio.NewScanner(res.Body)
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			var ev struct {
				State string `json:"state"`
			}
			if err := json.Unmarshal([]byte(data), &ev, json.RejectUnknownMembers(false)); err != nil {
				t.Fatal(err)
			}
			return ev.State
		}
	}
	t.Fatal("the wait stream sent no state")
	return ""
}

func (s *stack) requestState(t *testing.T, txn string) string {
	t.Helper()
	var st string
	s.query(t, "SELECT state FROM pc.approval_requests WHERE transaction_id = $1 ORDER BY created_at DESC LIMIT 1", []any{txn}, &st)
	return st
}

// TestE2E_M5p2_ApproveAndUseOnce is the M5 exit scenario through the gateway
// and the running server: a refund over $50 is held (S02); the Approver
// opens the emailed link and approves with a security key; the agent's
// long poll and stream both say READY; a changed amount is a new hold that
// never uses the old approval (S05); the resubmitted refund is dispatched
// once and a further resubmission gets the stored decision; a $125 refund
// is denied with no request (S03); revoking the grant while a refund is
// held refuses its resubmission (S04).
func TestE2E_M5p2_ApproveAndUseOnce(t *testing.T) {
	relay := smtptest.New(t)
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, relay: relay})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	alice, b, key := approver(t, s, people)

	// S02: held, with its wait handle.
	act := ids.NewV7()
	code, held := s.refund(t, act, "85.00")
	if code != http.StatusForbidden || held.ErrorClass != "held" || held.Decision != "REQUIRE_APPROVAL" || held.TransactionID == "" {
		t.Fatalf("an $85 refund = %d %+v", code, held)
	}
	if w := s.waitState(t, held.TransactionID, pantherclawv1.WaitState_WAIT_STATE_UNSPECIFIED); w.GetState() != pantherclawv1.WaitState_WAIT_STATE_PENDING {
		t.Fatalf("wait before the approval: %v", w)
	}
	// Routing emails bob the deep link.
	var link []string
	deadline := time.Now().Add(60 * time.Second)
	for link == nil && time.Now().Before(deadline) {
		for _, m := range relay.Messages() {
			if m.To == "bob@example.test" {
				body, _ := io.ReadAll(quotedprintable.NewReader(strings.NewReader(m.Data)))
				link = approvalLink.FindStringSubmatch(string(body))
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if link == nil {
		t.Fatalf("no approval link mailed to bob: %+v", relay.Messages())
	}
	if state := approveOnPage(t, b, key, link[2]); state != `"APPROVED"` {
		t.Fatalf("approval state %s", state)
	}
	if w := s.waitState(t, held.TransactionID, pantherclawv1.WaitState_WAIT_STATE_PENDING); w.GetState() != pantherclawv1.WaitState_WAIT_STATE_READY ||
		w.GetConsumeByTime() == nil {
		t.Fatalf("wait after the approval: %v", w)
	}
	if st := s.streamState(t, held.TransactionID); st != "READY" {
		t.Fatalf("wait stream after the approval: %s", st)
	}

	// S05: another amount is another action and a new hold; the approval
	// stays unused.
	if code, other := s.refund(t, ids.NewV7(), "90.00"); code != http.StatusForbidden || other.ErrorClass != "held" ||
		other.TransactionID == held.TransactionID {
		t.Fatalf("a changed amount = %d %+v", code, other)
	}
	if st := s.requestState(t, held.TransactionID); st != "APPROVED" {
		t.Fatalf("the approval after a changed amount: %s", st)
	}

	// The identical resubmission is dispatched once; again, the stored decision.
	calls := s.simCalls.Load()
	code, done := s.refund(t, act, "85.00")
	if code != http.StatusOK || done.TransactionID != held.TransactionID || s.simCalls.Load() != calls+1 {
		t.Fatalf("the resubmission = %d %+v (target calls %d)", code, done, s.simCalls.Load()-calls)
	}
	if st := s.requestState(t, held.TransactionID); st != "CONSUMED" {
		t.Fatalf("the used approval: %s", st)
	}
	if code, again := s.refund(t, act, "85.00"); code != http.StatusConflict || again.TransactionID != held.TransactionID || s.simCalls.Load() != calls+1 {
		t.Fatalf("a further resubmission = %d %+v", code, again)
	}

	// S03: over the grant, denied with no request.
	code, denied := s.refund(t, ids.NewV7(), "125.00")
	if code != http.StatusForbidden || denied.Decision != "DENY" {
		t.Fatalf("a $125 refund = %d %+v", code, denied)
	}
	var n int
	s.query(t, "SELECT count(*) FROM pc.approval_requests WHERE transaction_id = $1", []any{denied.TransactionID}, &n)
	if n != 0 {
		t.Fatalf("a denied refund has %d approval requests", n)
	}

	// S04: alice (now also Security Admin) revokes the grant while a
	// refund is held; its resubmission is refused and nothing is used.
	pending := ids.NewV7()
	code, h4 := s.refund(t, pending, "70.00")
	if code != http.StatusForbidden || h4.ErrorClass != "held" {
		t.Fatalf("a $70 refund = %d %+v", code, h4)
	}
	var aliceID, grant string
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'", nil, &aliceID)
	s.query(t, "SELECT id::text FROM pc.grants LIMIT 1", nil, &grant)
	if code, _, errs := alice.pclaw(t, "role", "bind", "--role", "security_admin", "--user", aliceID); code != 0 {
		t.Fatalf("role bind: %d %s", code, errs)
	}
	if code, _, errs := alice.pclaw(t, "grant", "revoke", grant, "--reason", "S04"); code != 0 {
		t.Fatalf("grant revoke: %d %s", code, errs)
	}
	if code, r := s.refund(t, pending, "70.00"); code != http.StatusForbidden || r.ErrorClass == "held" || r.Outcome != "" {
		t.Fatalf("the resubmission after revocation = %d %+v", code, r)
	}
	if st := s.requestState(t, h4.TransactionID); st == "APPROVED" || st == "CONSUMED" {
		t.Fatalf("the request after revocation: %s", st)
	}
}
