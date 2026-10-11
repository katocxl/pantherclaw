// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

// reconcilerOnPage makes rita a Reconciler, invited by alice (the org's
// administrator), signed in in her browser with a security key on her
// account. Releasing needs no cooldown: only independence and the key.
func reconcilerOnPage(t *testing.T, s *stack, people *m2Stack) (*browser, *webauthntest.Authenticator) {
	t.Helper()
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", s.serverCfg, "--org", org}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	code, invite, errs := alice.pclaw(t, "invite", "create", "--email", "rita@example.test", "--role", "reconciler")
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite rita: %d %s %s", code, invite, errs)
	}
	rita := people.user(t, "rita", "rita@example.test")
	rita.login(t, org, pciToken.FindStringSubmatch(invite)[1])
	b := newBrowser(people)
	b.signIn(t, org, "rita", "rita@example.test", true)
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
	return b, key
}

var shownEvidence = regexp.MustCompile(`data-evidence="([0-9a-f-]{36})"`)

// releaseOnPage opens the reconciliation page and releases the unknown
// outcome with the key, as the page's script does; it returns the state.
func releaseOnPage(t *testing.T, b *browser, key *webauthntest.Authenticator, task, basis string) string {
	t.Helper()
	path := "/reconciliations/" + task
	code, page := b.page(t, path)
	if code != http.StatusOK || !strings.Contains(page, "payments.refund.create") || !strings.Contains(page, `id="release"`) {
		t.Fatalf("reconciliation page: %d %s", code, page)
	}
	evidence := []string{}
	for _, m := range shownEvidence.FindAllStringSubmatch(page, -1) {
		evidence = append(evidence, m[1])
	}
	if len(evidence) == 0 {
		t.Fatal("the page shows no evidence from the verifier")
	}
	code, body := b.post(t, path+"/release-options", map[string]any{"basis": basis, "evidence": evidence})
	if code != http.StatusOK {
		t.Fatalf("release options: %d %v", code, body)
	}
	resp, err := key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	code, out := b.post(t, path+"/release", map[string]any{
		"ceremony": body["ceremony"], "response": jsontext.Value(resp), "basis": basis, "evidence": body["evidence"],
		"expires_at": body["expires_at"],
	})
	if code != http.StatusOK {
		t.Fatalf("release: %d %v", code, out)
	}
	return string(out["state"])
}

// TestE2E_M7_UnknownRefundReleasedByPerson is S07 completed with a hang
// before the effect (G0 M7 exit): the target never answers and never
// refunds, so the outcome is UNKNOWN, its budget stays held and an exact
// repeat waits. The verifier's lookup finds nothing. An independent
// Reconciler opens the reconciliation page, writes a basis and releases it
// with a security key: the budget and the repeat protection are released,
// the release is recorded with the person and the key, the waitlist entry
// closes, and an exact repeat is decided again (and dispatched).
func TestE2E_M7_UnknownRefundReleasedByPerson(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{
		budget: "1000.00", faults: payments.Faults{HangRate: 1, HangFor: time.Minute}, timeout: 500 * time.Millisecond, people: &p,
	})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
		t.Fatalf("the hang: %d %+v", code, r)
	}
	if reserved, _, permit := s.budget(t, r.TransactionID); reserved != "30" || permit != "UNKNOWN" {
		t.Fatalf("held: reserved %s permit %s", reserved, permit)
	}
	task := s.row(t, "SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'unknown_outcome'", r.TransactionID)
	if task == "" || s.row(t, `SELECT e.state FROM pc.reconciliation_tasks t JOIN pc.waitlist_entries e
		ON e.org_id = t.org_id AND e.id = t.waitlist_entry_id WHERE t.id = $1`, task) != "OPEN" {
		t.Fatalf("no reconciliation linked to an open waitlist entry for %s", r.TransactionID)
	}

	// An exact repeat waits while nobody knows (HR-007); nothing is sent.
	calls := s.simCalls.Load()
	if code, again := s.refund(t, ids.NewV7(), "30.00"); code == http.StatusOK || s.simCalls.Load() != calls ||
		s.row(t, "SELECT reason_code FROM pc.transactions WHERE id = $1", again.TransactionID) != "RECONCILIATION_REQUIRED" {
		t.Fatalf("a repeat while unknown: %d %+v", code, again)
	}

	// The verifier reads the target through the gateway and finds nothing.
	s.eventually(t, "true", "SELECT (count(*) > 0)::text FROM pc.observations WHERE transaction_id = $1", r.TransactionID)
	if got := s.row(t, "SELECT state FROM pc.reconciliation_tasks WHERE id = $1", task); got != "OPEN" {
		t.Fatalf("evidence of nothing resolved the task: %s", got)
	}

	b, key := reconcilerOnPage(t, s, people)
	basis := "The processor shows no refund on ch_1 since the call; its request log ends before our idempotency key."
	if state := releaseOnPage(t, b, key, task, basis); state != `"NOT_OCCURRED"` {
		t.Fatalf("released: %s", state)
	}
	rita := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'rita'")
	if got := s.row(t, `SELECT state || ' ' || resolved_via || ' ' || user_id::text || ' ' || (credential_id IS NOT NULL)::text || ' ' ||
		(session_id IS NOT NULL)::text || ' ' || (octet_length(signature) > 0)::text || ' ' || cardinality(evidence)::text
		FROM pc.reconciliation_tasks WHERE id = $1`, task); !strings.HasPrefix(got, "NOT_OCCURRED person "+rita+" true true true ") ||
		strings.HasSuffix(got, " 0") {
		t.Fatalf("the release %q", got)
	}
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "0" || spent != "0" {
		t.Fatalf("after the release: reserved %s spent %s, want released", reserved, spent)
	}
	if got := s.row(t, "SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1", r.TransactionID); got != "RELEASED" {
		t.Fatalf("claim %q", got)
	}
	if got := s.row(t, "SELECT state || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID); got != "NONE_CONFIRMED person" {
		t.Fatalf("effect receipt %q", got)
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.transaction.reconciliation_released' AND actor_id = $1", rita); got != "1" {
		t.Fatalf("%s release entries", got)
	}
	if got := s.row(t, "SELECT state || ' ' || decision_reason FROM pc.waitlist_entries WHERE kind = 'RECONCILIATION' AND subject_id = $1", r.TransactionID); got != "APPROVED NOT_OCCURRED" {
		t.Fatalf("waitlist entry %q", got)
	}
	// Released once: the page offers nothing more.
	if code, page := b.page(t, "/reconciliations/"+task); code != http.StatusOK || strings.Contains(page, `id="release"`) {
		t.Fatalf("the page after the release: %d", code)
	}

	// An exact repeat is decided again, and sent.
	calls = s.simCalls.Load()
	code, again := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusGatewayTimeout || s.simCalls.Load() != calls+1 ||
		s.row(t, "SELECT decision FROM pc.transactions WHERE id = $1", again.TransactionID) != "ALLOW" {
		t.Fatalf("a repeat after the release: %d %+v (target calls %d)", code, again, s.simCalls.Load()-calls)
	}
}
