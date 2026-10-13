// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The refund scenarios that need M5 part 2's approvals, through the mTLS
// gateway with the approver keys file it pins (G0 M6 slice 23: S02, S03,
// S04, S05, HR-011, HR-038, T-030), and a held refund that becomes an MCP
// task.

// approvalStack starts the refund stack with people, and bob as an
// Approver whose key alice exported for the gateway.
func approvalStack(t *testing.T) (*stack, *user, *browser, *webauthntest.Authenticator) {
	t.Helper()
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p})
	alice, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
	return s, alice, b, key
}

// requestOf is the latest approval request of a transaction, or "".
func (s *stack) requestOf(t *testing.T, txn string) string {
	t.Helper()
	var id string
	s.query(t, `SELECT coalesce((SELECT id::text FROM pc.approval_requests WHERE transaction_id = $1 ORDER BY created_at DESC LIMIT 1), '')`,
		[]any{txn}, &id)
	return id
}

// approve has bob approve the transaction's request on its page.
func (s *stack) approve(t *testing.T, b *browser, key *webauthntest.Authenticator, txn string) {
	t.Helper()
	if state := approveOnPage(t, b, key, "/approvals/"+s.requestOf(t, txn)+"?org="+s.org.String()); state != `"APPROVED"` {
		t.Fatalf("approval state %s", state)
	}
}

// TestS02_AnApprovedRefundIsDispatchedThroughTheGateway: an $85 refund is
// held for an approver; bob approves it with his security key; the agent
// resubmits the identical refund, whose permit carries bob's assertion,
// and the gateway verifies it against the pinned keys before dispatching
// it once.
func TestS02_AnApprovedRefundIsDispatchedThroughTheGateway(t *testing.T) {
	s, _, b, key := approvalStack(t)
	act := ids.NewV7()
	code, held := s.refund(t, act, "85.00")
	if code != http.StatusForbidden || held.ErrorClass != "held" || held.Decision != "REQUIRE_APPROVAL" || s.simCalls.Load() != 0 {
		t.Fatalf("S02 hold: %d %+v", code, held)
	}
	s.approve(t, b, key, held.TransactionID)
	code, done := s.refund(t, act, "85.00")
	if code != http.StatusOK || done.Outcome != "ACCEPTED" || done.TransactionID != held.TransactionID || s.simCalls.Load() != 1 {
		t.Fatalf("S02 resubmission: %d %+v (target calls %d)", code, done, s.simCalls.Load())
	}
	if st := s.requestState(t, held.TransactionID); st != "CONSUMED" {
		t.Fatalf("S02 approval %s", st)
	}
	s.waitSettled(t, "85")
}

// TestS03_ARefundOverTheGrantIsDeniedEvenIfAManagerTriesToApprove: a $125
// refund is over the grant's $100, so it is denied with no approval
// request: there is nothing an Approver (or an admin) can approve, and the
// resubmission is denied again with nothing sent.
func TestS03_ARefundOverTheGrantIsDeniedEvenIfAManagerTriesToApprove(t *testing.T) {
	s, alice, b, _ := approvalStack(t)
	act := ids.NewV7()
	code, denied := s.refund(t, act, "125.00")
	if code != http.StatusForbidden || denied.Decision != "DENY" {
		t.Fatalf("S03: %d %+v", code, denied)
	}
	if req := s.requestOf(t, denied.TransactionID); req != "" {
		t.Fatalf("a denied refund has approval request %s", req)
	}
	if status, _ := b.page(t, "/approvals/"+denied.TransactionID+"?org="+s.org.String()); status != http.StatusNotFound {
		t.Fatalf("the approver opened an approval page for a denied refund: %d", status)
	}
	if code, out, _ := alice.pclaw(t, "approval", "list"); code != 0 || strings.Contains(out, denied.TransactionID) {
		t.Fatalf("approval list: %d %s", code, out)
	}
	if code, again := s.refund(t, act, "125.00"); code != http.StatusForbidden || again.Decision != "DENY" || s.simCalls.Load() != 0 {
		t.Fatalf("S03 resubmission: %d %+v", code, again)
	}
}

// TestS04_RevokingTheGrantWhileHeldInvalidatesTheApproval: alice revokes
// the grant while a refund waits for approval; the janitor invalidates the
// request (GRANT_REVOKED), and the resubmission is denied with nothing
// sent.
func TestS04_RevokingTheGrantWhileHeldInvalidatesTheApproval(t *testing.T) {
	s, alice, _, _ := approvalStack(t)
	act := ids.NewV7()
	code, held := s.refund(t, act, "70.00")
	if code != http.StatusForbidden || held.ErrorClass != "held" {
		t.Fatalf("S04 hold: %d %+v", code, held)
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
	// The janitor's sweep, as its periodic job runs it.
	if _, err := apapp.SweepOrg(context.Background(), s.pool, nil, s.org); err != nil {
		t.Fatal(err)
	}
	var state string
	s.query(t, "SELECT state || '/' || coalesce(end_reason, '') FROM pc.approval_requests WHERE id = $1", []any{s.requestOf(t, held.TransactionID)}, &state)
	if state != "INVALIDATED/GRANT_REVOKED" {
		t.Fatalf("S04 request %s", state)
	}
	if code, r := s.refund(t, act, "70.00"); code != http.StatusForbidden || r.Decision != "DENY" || s.simCalls.Load() != 0 {
		t.Fatalf("S04 resubmission: %d %+v", code, r)
	}
}

// TestS05_AChangedAmountAfterApprovalIsANewDecision: after bob approved an
// $85 refund, a $90 one is a new action with its own hold, and the same
// action id with $90 is tampering: denied, and it closes the action, so
// the approval is never used.
func TestS05_AChangedAmountAfterApprovalIsANewDecision(t *testing.T) {
	s, _, b, key := approvalStack(t)
	act := ids.NewV7()
	code, held := s.refund(t, act, "85.00")
	if code != http.StatusForbidden || held.ErrorClass != "held" {
		t.Fatalf("S05 hold: %d %+v", code, held)
	}
	s.approve(t, b, key, held.TransactionID)
	if code, other := s.refund(t, ids.NewV7(), "90.00"); code != http.StatusForbidden || other.ErrorClass != "held" ||
		other.TransactionID == held.TransactionID {
		t.Fatalf("S05 another amount: %d %+v", code, other)
	}
	if code, r := s.refund(t, act, "90.00"); code != http.StatusForbidden || r.Decision != "DENY" || len(r.Reasons) == 0 ||
		r.Reasons[0] != "ACTION_TAMPERED" {
		t.Fatalf("S05 the approved action with another amount: %d %+v", code, r)
	}
	if code, r := s.refund(t, act, "85.00"); code == http.StatusOK || s.simCalls.Load() != 0 {
		t.Fatalf("S05 the approved amount after tampering: %d %+v (target calls %d)", code, r, s.simCalls.Load())
	}
	if st := s.requestState(t, held.TransactionID); st == "CONSUMED" {
		t.Fatal("S05 the approval was used")
	}
}

// signOver has key sign challenge as a browser would on the approval
// page, and returns the authenticator data, client data and signature.
func signOver(t *testing.T, key *webauthntest.Authenticator, challenge []byte) (authData, clientData, sig []byte) {
	t.Helper()
	opts, _ := json.Marshal(map[string]any{"publicKey": map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString(challenge), "rpId": "localhost",
		"allowCredentials": []map[string]any{{"id": base64.RawURLEncoding.EncodeToString(key.CredentialID()), "type": "public-key"}},
	}})
	raw, err := key.Assert(opts)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Response struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJSON"`
			Signature         string `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(raw, &r, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return dec(r.Response.AuthenticatorData), dec(r.Response.ClientDataJSON), dec(r.Response.Signature)
}

// TestT030_AnApprovalForgedInTheDatabaseIsRefusedByTheGateway (HR-038): an
// operator with direct database access forges bob's approval of a held
// refund, once with a key of their own that they register for bob in the
// database and use to sign the binding, and once with bob's real key but
// no valid signature. The Authority, reading the database, issues permits
// that carry these assertions; the gateway checks them against the keys
// its operator pinned and refuses both before BeginDispatch, so nothing is
// sent.
func TestT030_AnApprovalForgedInTheDatabaseIsRefusedByTheGateway(t *testing.T) {
	s, _, _, _ := approvalStack(t)
	var bob, session, bobKey string
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'bob'", nil, &bob)
	s.query(t, "SELECT id::text FROM pc.sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", []any{bob}, &session)
	s.query(t, "SELECT id::text FROM pc.webauthn_credentials WHERE user_id = $1", []any{bob}, &bobKey)
	mallory, err := webauthntest.New(s.apiURL, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	cose, err := mallory.COSEKey()
	if err != nil {
		t.Fatal(err)
	}
	malloryKey := ids.NewV7().String()
	s.db.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'Desk key', now() - interval '30 days')`,
		s.org, malloryKey, bob, mallory.CredentialID(), cose)

	forge := func(amount string, sign func(binding []byte) (key string, authData, clientData, sig []byte)) {
		t.Helper()
		act := ids.NewV7()
		code, held := s.refund(t, act, amount)
		if code != http.StatusForbidden || held.ErrorClass != "held" {
			t.Fatalf("hold: %d %+v", code, held)
		}
		req := s.requestOf(t, held.TransactionID)
		var binding []byte
		s.query(t, "SELECT binding FROM pc.approval_requests WHERE id = $1", []any{req}, &binding)
		key, ad, cd, sig := sign(binding)
		s.db.AdminExec(t, `INSERT INTO pc.approval_responses (org_id, id, request_id, user_id, session_id, kind, requirement,
			credential_id, authenticator_data, client_data_json, signature) VALUES ($1, $2, $3, $4, $5, 'APPROVE', 0, $6, $7, $8, $9)`,
			s.org, ids.NewV7(), req, bob, session, key, ad, cd, sig)
		s.db.AdminExec(t, `UPDATE pc.approval_requests SET state = 'APPROVED', approved_at = now(),
			consume_by = least(now() + interval '15 minutes', deadline_at) WHERE id = $1`, req)
		code, r := s.refund(t, act, amount)
		if code != http.StatusBadGateway || r.ErrorClass != "enforcement_failed" || r.Error != "approval_unverified" {
			t.Fatalf("a forged approval: %d %+v", code, r)
		}
		if s.simCalls.Load() != 0 {
			t.Fatalf("a forged approval reached the target %d times", s.simCalls.Load())
		}
		var dispatched int
		s.query(t, "SELECT count(*) FROM pc.permits WHERE transaction_id = $1 AND dispatching_at IS NOT NULL", []any{held.TransactionID}, &dispatched)
		if dispatched != 0 {
			t.Fatal("a forged approval reached BeginDispatch")
		}
	}
	// A key the operator added in the database signs the binding: valid,
	// but not pinned.
	forge("85.00", func(binding []byte) (string, []byte, []byte, []byte) {
		ad, cd, sig := signOver(t, mallory, binding)
		return malloryKey, ad, cd, sig
	})
	// Bob's pinned key, with an assertion nobody signed.
	forge("86.00", func(binding []byte) (string, []byte, []byte, []byte) {
		ad, cd, sig := signOver(t, mallory, binding)
		sig[len(sig)-1] ^= 1
		return bobKey, ad, cd, sig
	})
}

// TestE2E_M6_AHeldRefundBecomesAnMCPTask: an MCP client that declares the
// tasks extension asks, through pclaw mcp proxy, for an $85 refund; it is
// held, so the gateway answers with a task (HR-185). Once bob approves, the
// client's next tasks/get resubmits the held action, the permit's approval
// verifies against the pinned keys, and the task completes with the refund.
func TestE2E_M6_AHeldRefundBecomesAnMCPTask(t *testing.T) {
	s, _, b, key := approvalStack(t)
	const meta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`
	var held struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Status     string `json:"status"`
		} `json:"result"`
	}
	answer := s.mcpProxy(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund","arguments":`+
		`{"charge":"ch_1","amount":"85.00","currency":"USD","reason":"duplicate"},`+meta+`}}`)[1]
	if err := json.Unmarshal([]byte(answer), &held, json.RejectUnknownMembers(false)); err != nil || held.Result.ResultType != "task" ||
		held.Result.Status != "working" || held.Result.TaskID == "" || s.simCalls.Load() != 0 {
		t.Fatalf("a held refund over MCP: %s", answer)
	}
	var txn string
	s.query(t, "SELECT transaction_id::text FROM pc.approval_requests ORDER BY created_at DESC LIMIT 1", nil, &txn)
	s.approve(t, b, key, txn)
	poll := `{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"taskId":"` + held.Result.TaskID + `",` + meta + `}}`
	done := s.mcpProxy(t, poll)[2]
	if !strings.Contains(done, `"status":"completed"`) || !strings.Contains(done, `"isError":false`) || s.simCalls.Load() != 1 {
		t.Fatalf("the task after the approval: %s (target calls %d)", done, s.simCalls.Load())
	}
	if st := s.requestState(t, txn); st != "CONSUMED" {
		t.Fatalf("the approval after the task completed: %s", st)
	}
}
