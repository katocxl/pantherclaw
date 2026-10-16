// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/gateway"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
)

// refundOf sends a refund of charge for amount as a workload, in run. It
// returns the status and the body: the target's answer with the gateway's
// PC-Outcome header prepended, or the gateway's refusal.
func (s *m3Stack) refundOf(t *testing.T, key ed25519.PrivateKey, token, run, charge, amount string) (int, string) {
	t.Helper()
	body := `{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate"}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/payments/v1/refunds", strings.NewReader(body))
	req.Header.Set(gateway.HeaderRunID, run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	c := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key, Token: func() string { return token }}}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if o := resp.Header.Get("PC-Outcome"); o != "" {
		return resp.StatusCode, `"outcome":"` + o + `" ` + string(b)
	}
	return resp.StatusCode, string(b)
}

// TestE2E_M4_GrantsDelegationRevocationAndCounters is the M4 exit
// scenario (G0 M4 part 2, exit criteria; S10). Through the gateway: a
// person issues a grant with pclaw and starts a run with it; a refund
// within it is allowed and one over it is denied. The workload delegates a
// narrower grant to a child run, which can exceed neither itself nor its
// parent, and revoking the parent denies the child. Two concurrent refunds
// against a one-refund counter get one permit. Facts come from a provider's
// own service account, reported with pclaw.
func TestE2E_M4_GrantsDelegationRevocationAndCounters(t *testing.T) {
	s := startM3(t)
	alice := s.user(t, "alice", "alice@example.test")
	alice.login(t, s.org, s.bootstrap)
	must := func(args ...string) string {
		t.Helper()
		code, o, e := alice.pclaw(t, args...)
		if code != 0 {
			t.Fatalf("pclaw %s: %d %s %s", strings.Join(args, " "), code, o, e)
		}
		return o
	}
	team := field(t, must("team", "create", "--slug", "payments", "--name", "Payments"), "id")
	env := field(t, must("env", "create", "--team", team, "--slug", "prod", "--name", "Production", "--kind", "prod"), "id")
	var users struct {
		Users []struct {
			ID string `json:"id"`
		} `json:"users"`
	}
	_ = json.Unmarshal([]byte(must("user", "list")), &users)
	aliceID := users.Users[0].ID
	for _, role := range []string{"agent_owner", "agent_admitter", "run_launcher", "grant_issuer", "policy_publisher"} {
		must("role", "bind", "--role", role, "--user", aliceID)
	}

	// An admitted workload of a refund agent.
	agent := field(t, must("agent", "create", "--name", "refunder", "--team", team, "--env", env, "--owner", aliceID, "--context", "service"), "id")
	work := t.TempDir()
	enrollFile, keyFile := filepath.Join(work, "enroll.token"), filepath.Join(work, "workload.json")
	must("agent", "enroll-token", agent, "--out", enrollFile)
	must("workload", "init", "--key-file", keyFile)
	o := must("workload", "enroll", "--key-file", keyFile, "--server", s.url, "--enrollment-token-file", enrollFile)
	inst, fp := enrolledInstance.FindStringSubmatch(o), enrolledPrint.FindStringSubmatch(o)
	if inst == nil || fp == nil {
		t.Fatalf("enroll output %q", o)
	}
	must("instance", "admit", inst[1], "--fingerprint", fp[1])
	token := strings.TrimSpace(must("workload", "token", "--key-file", keyFile))
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := kf.Key()

	// The reference package (seeded: no test server trusts a package root),
	// and a billing provider whose own service account reports facts.
	seedPackage(t, s.db.AppPool(t), ids.MustParse[ids.Org](s.org))
	s.connect(t)
	sa := field(t, must("sa", "create", "--name", "billing"), "id")
	must("role", "bind", "--role", "fact_provider", "--sa", sa)
	secret := field(t, must("apikey", "create", "--sa", sa, "--name", "billing", "--scope", "fact.write"), "secret")
	must("fact-provider", "register", "--name", "billing", "--sa", sa, "--fact", "payments.charge.refundable:boolean:payments.charge:5m")
	billing := s.user(t, "billing", "")
	value := filepath.Join(work, "true.json")
	if err := os.WriteFile(value, []byte(`{"bool": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"ch_1", "ch_2", "ch_3", "ch_4", "ch_5", "ch_6", "ch_7", "ch_8"} {
		var out, errb bytes.Buffer
		code := pclaw.Run(context.Background(), []string{
			"fact", "put", "--name", "payments.charge.refundable", "--subject-type", "payments.charge", "--subject-id", c, "--value-file", value,
		}, &out, &errb, billing.env("PANTHERCLAW_SERVER", s.url, "PANTHERCLAW_API_KEY", secret), pclaw.Options{})
		var put struct {
			Results []struct {
				Accepted bool `json:"accepted"`
			} `json:"results"`
		}
		if code != 0 || json.Unmarshal(out.Bytes(), &put) != nil || len(put.Results) != 1 || !put.Results[0].Accepted {
			t.Fatalf("fact put %s: %d %s %s", c, code, out.String(), errb.String())
		}
	}
	if code, _, e := alice.pclaw(t, "fact", "put", "--name", "payments.charge.refundable", "--subject-type", "payments.charge",
		"--subject-id", "ch_9", "--value-file", value); code != 1 {
		t.Fatalf("a person reported a fact: %d %s", code, e)
	}

	// The grant: refunds up to $100 each from a $500 task budget, one level
	// of delegation.
	doc := func(name, content string) string {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bounds := doc("bounds.json", `{"operations": ["payments.refund.create"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`)
	limits := doc("limits.json", `{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "500.00", "period": "none"}]}`)
	// The environment is a PRODUCTION one, so the grant needs the agent
	// promoted for refunds first (G0 M11 part 2 D39, HR-290): the checks
	// run for real, as a fleet manager with a fresh step-up of their key.
	if code, _, e := alice.pclaw(t, "grant", "issue", agent, "--principal", "user:"+aliceID, "--expires", "24h", "--bounds-file", bounds); code == 0 ||
		!strings.Contains(e, "NOT_PROMOTED") {
		t.Fatalf("a production grant before the promotion: %d %s", code, e)
	}
	pool := s.db.AppPool(t)
	org := ids.MustParse[ids.Org](s.org)
	var conn ids.UUID
	if err := pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.connections WHERE name = 'payments'").Scan(&conn)
	}); err != nil {
		t.Fatal(err)
	}
	promotiontest.Promote(t, promotiontest.Scope{Pool: pool, Org: org, Agent: mustUUID(t, agent), Env: mustUUID(t, env), Connection: conn},
		"payments.refund.create")
	grant := field(t, must("grant", "issue", agent, "--principal", "user:"+aliceID, "--expires", "24h", "--bounds-file", bounds,
		"--limits-file", limits, "--delegation-depth", "1", "--max-children", "2", "--task", "refunds"), "id")
	run := field(t, must("run", "start", agent, "--instance", inst[1], "--grant", grant, "--task", "refunds"), "id")
	allowed := func(what, run, charge, amount string) {
		t.Helper()
		if code, body := s.refundOf(t, key, token, run, charge, amount); code != http.StatusOK || !strings.Contains(body, `"outcome":"ACCEPTED"`) {
			t.Fatalf("%s: %d %s", what, code, body)
		}
	}
	denied := func(what, run, charge, amount, reason string) {
		t.Helper()
		if code, body := s.refundOf(t, key, token, run, charge, amount); code != http.StatusForbidden || !strings.Contains(body, `"DENY"`) ||
			!strings.Contains(body, reason) {
			t.Errorf("%s: %d %s, want DENY %s", what, code, body, reason)
		}
	}
	allowed("a refund within the grant", run, "ch_1", "30.00")
	denied("a refund over the grant", run, "ch_2", "125.00", "GRANT_LIMIT_EXCEEDED")
	var budget struct {
		Accounts []struct {
			Spent    string `json:"spent"`
			Reserved string `json:"reserved"`
		} `json:"accounts"`
	}
	if b := must("grant", "budget", grant); json.Unmarshal([]byte(b), &budget) != nil || len(budget.Accounts) != 1 ||
		budget.Accounts[0].Spent != "30" || budget.Accounts[0].Reserved != "0" {
		t.Errorf("budget state after one refund: %s", b)
	}

	// S10: the workload delegates at most $20 a refund to a child run.
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key, Token: func() string { return token }},
	}, s.url)))
	ctx := context.Background()
	child, err := wc.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: run, AgentId: agent})
	if err != nil {
		t.Fatal(err)
	}
	childRun := child.GetRun().GetId()
	delegated, err := wc.DelegateGrant(ctx, &pantherclawv1.DelegateGrantRequest{
		RunId: run, ChildRunId: childRun, Bounds: []byte(`{"operations": ["payments.refund.create"],
		  "params": {"payments.refund.create": {"amount": {"max": {"USD": "20.00"}}}}}`),
	})
	if err != nil || delegated.GetGrant().GetParentGrantId() != grant || delegated.GetGrant().GetDepth() != 1 {
		t.Fatalf("DelegateGrant = %v, %v", delegated, err)
	}
	if _, err := wc.DelegateGrant(ctx, &pantherclawv1.DelegateGrantRequest{
		RunId: run, ChildRunId: childRun, Bounds: []byte(`{"operations": ["payments.refund.create", "payments.refund.get"]}`),
	}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a second, wider delegation: %v", err)
	}
	allowed("a child refund within its grant", childRun, "ch_3", "15.00")
	denied("a child refund over its own grant", childRun, "ch_4", "50.00", "GRANT_LIMIT_EXCEEDED")
	denied("a child refund over its parent", childRun, "ch_4", "150.00", "GRANT_LIMIT_EXCEEDED")
	if l := must("grant", "list", "--parent", grant); !strings.Contains(l, delegated.GetGrant().GetId()) {
		t.Errorf("the delegated grant is not listed under its parent: %s", l)
	}

	// Revoking the parent revokes the child at once.
	var revoked struct {
		Revoked int `json:"revoked"`
	}
	if r := must("grant", "revoke", grant, "--reason", "done"); json.Unmarshal([]byte(r), &revoked) != nil || revoked.Revoked != 2 {
		t.Errorf("revoke: %s", r)
	}
	denied("the child after the revocation", childRun, "ch_5", "10.00", "GRANT_REVOKED")
	denied("the parent after the revocation", run, "ch_5", "10.00", "GRANT_REVOKED")

	// A one-refund counter: two concurrent refunds get one permit.
	once := doc("once.json", `{"counters": [{"id": "once", "operations": ["payments.refund.create"], "key": "task", "window": "none", "max": "1"}]}`)
	single := field(t, must("grant", "issue", agent, "--principal", "user:"+aliceID, "--expires", "24h", "--bounds-file", bounds,
		"--limits-file", once, "--task", "one refund"), "id")
	onceRun := field(t, must("run", "start", agent, "--instance", inst[1], "--grant", single), "id")
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for _, c := range []string{"ch_6", "ch_7"} {
		wg.Go(func() {
			code, _ := s.refundOf(t, key, token, onceRun, c, "10.00")
			mu.Lock()
			codes[code]++
			mu.Unlock()
		})
	}
	wg.Wait()
	if codes[http.StatusOK] != 1 || codes[http.StatusForbidden] != 1 {
		t.Fatalf("two concurrent refunds against a one-refund counter: %v, want one accepted", codes)
	}
	denied("a third refund against the counter", onceRun, "ch_8", "10.00", "COUNT_LIMIT_REACHED")
}
