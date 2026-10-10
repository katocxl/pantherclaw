// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package workloadrpc_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// waiter is an admitted instance of the org's agent with a workload token.
type waiter struct {
	instance ids.UUID
	key      ed25519.PrivateKey
	token    string
}

func (o *renewOrg) waiter(t *testing.T, s *stack) waiter {
	t.Helper()
	ctx := t.Context()
	et, err := o.identity.CreateEnrollmentToken(ctx, &pantherclawv1.CreateEnrollmentTokenRequest{AgentId: o.agent})
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(nil)
	wc := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{Key: key}))
	jwk, _ := json.Marshal(jws.PublicJWK(pub, ""))
	e, err := wc.Enroll(ctx, &pantherclawv1.EnrollRequest{EnrollmentToken: et.GetToken(), PublicJwk: string(jwk)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.identity.AdmitInstance(ctx, &pantherclawv1.AdmitInstanceRequest{Id: e.GetInstanceId(), Fingerprint: e.GetFingerprint()}); err != nil {
		t.Fatal(err)
	}
	res, err := wc.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: e.GetIdentifier()})
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := ids.ParseUUID(e.GetInstanceId())
	return waiter{instance: inst, key: key, token: res.GetWorkloadToken()}
}

// held inserts a run bound to w's instance, a held transaction and its
// PENDING approval request, and returns the transaction and the request.
func (o *renewOrg) held(t *testing.T, s *stack, w waiter) (txn, request ids.UUID) {
	t.Helper()
	user, run, grant := ids.NewV7(), ids.NewV7(), ids.NewV7()
	txn, request = ids.NewV7(), ids.NewV7()
	agent, _ := ids.ParseUUID(o.agent)
	s.exec(t, o.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", o.org, user, user.String())
	s.exec(t, o.org, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind, grantor_id, basis)
		SELECT $1, $2, id, $3, environment_id, 0, 1, 'user', $3, 'test' FROM pc.agents WHERE id = $4`, o.org, grant, user, agent)
	s.exec(t, o.org, `INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id, principal_source, grant_id, expires_at)
		SELECT $1, $2, id, $3, environment_id, $4, $4, 'launcher', $5, now() + interval '8 hours' FROM pc.agents WHERE id = $6`,
		o.org, run, w.instance, user, grant, agent)
	s.exec(t, o.org, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'R', 'gw', 'OPEN')`, o.org, txn, run, ids.NewV7(), make([]byte, 32))
	b := append(append([]byte{}, request[:]...), request[:]...)
	s.exec(t, o.org, `INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
		grant_revision, variant_key, operation, binding, binding_input, requirements, display, display_hash, action_ir, deadline_at)
		VALUES ($1, $2, 'ACTION', $3, $4, 1, $5, $6, 1, $7, 'payments.refund.create', $7, '\x7b7d',
		'[{"kind":"approval","role":"approver","count":1,"sources":[]}]', '{}', $7, '\x7b7d', date_trunc('second', now()) + interval '1 hour')`,
		o.org, request, agent, txn, run, grant, b)
	return txn, request
}

func (s *stack) wait(t *testing.T, w waiter, txn ids.UUID) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, s.url+workloadrpc.WaitPath+txn.String(), nil)
	resp, err := (&http.Client{Transport: &workloadclient.Transport{Key: w.key, Token: func() string { return w.token }}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// next reads the next state event's data.
func next(t *testing.T, r *bufio.Reader) map[string]any {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended: %v", err)
		}
		if data, ok := strings.CutPrefix(line, "data: "); ok {
			var v map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &v); err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
}

// TestHR174_TheWaitStreamServesOnlyTheRunsInstance: GET /v1/wait/{txn}
// with PAP/1 credentials of the instance the run is bound to streams the
// state (no notes, no display) until it is final; another instance gets
// 404, a request without credentials 401, and a second stream beyond the
// instance's limit 429.
func TestHR174_TheWaitStreamServesOnlyTheRunsInstance(t *testing.T) {
	s := newStack(t)
	o := newRenewOrg(t, s)
	w := o.waiter(t, s)
	txn, request := o.held(t, s, w)

	resp := s.wait(t, w, txn)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	r := bufio.NewReader(resp.Body)
	v := next(t, r)
	if v["state"] != "PENDING" || v["handle"] != txn.String() || v["approval_request_id"] != request.String() || v["retry_after_seconds"] != 5.0 {
		t.Fatalf("first event %v", v)
	}
	if busy := s.wait(t, w, txn); busy.StatusCode != http.StatusTooManyRequests || busy.Header.Get("Retry-After") != "5" {
		t.Fatalf("a second stream: %d", busy.StatusCode)
	}
	other := o.waiter(t, s)
	if resp := s.wait(t, other, txn); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another instance: %d", resp.StatusCode)
	}
	if resp, err := http.Get(s.url + workloadrpc.WaitPath + txn.String()); err != nil || resp.StatusCode != http.StatusUnauthorized ||
		resp.Header.Get("PAP-Error") == "" {
		t.Fatalf("no credentials: %v %v", resp, err)
	}

	s.exec(t, o.org, "UPDATE pc.approval_requests SET state = 'DECLINED', end_reason = 'APPROVAL_DECLINED', ended_at = now() WHERE id = $1", request)
	if v := next(t, r); v["state"] != "DECLINED" || v["code"] != "APPROVAL_DECLINED" || v["retry_after_seconds"] != 0.0 {
		t.Fatalf("change %v", v)
	}
	if _, err := r.ReadString('\n'); err == nil {
		if rest, _ := r.ReadString('\n'); rest != "" {
			t.Fatalf("the stream continued after a final state: %q", rest)
		}
	}
}

// TestHR174_TheWorkloadWaitsGivesEvidenceAndAsksForAccess: through
// WorkloadService the run's instance long-polls its held transaction,
// gives evidence and asks for access citing a scope denial; another
// instance gets "not found".
func TestHR174_TheWorkloadWaitsGivesEvidenceAndAsksForAccess(t *testing.T) {
	s := newStack(t)
	o := newRenewOrg(t, s)
	w := o.waiter(t, s)
	txn, request := o.held(t, s, w)
	var run string
	if err := s.pool.InTenantTx(t.Context(), o.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT run_id::text FROM pc.transactions WHERE id = $1", txn).Scan(&run)
	}); err != nil {
		t.Fatal(err)
	}
	client := func(x waiter) pantherclawv1connect.WorkloadServiceClient {
		return pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{Key: x.key, Token: func() string { return x.token }}))
	}
	wc := client(w)
	res, err := wc.Wait(t.Context(), &pantherclawv1.WaitRequest{
		RunId: run, Handle: txn.String(), KnownState: pantherclawv1.WaitState_WAIT_STATE_PENDING, TimeoutSeconds: 1,
	})
	if err != nil || !res.GetTimedOut() || res.GetWait().GetState() != pantherclawv1.WaitState_WAIT_STATE_PENDING ||
		res.GetWait().GetApprovalRequestId() != request.String() {
		t.Fatalf("wait: %v, %v", res, err)
	}
	if _, err := client(o.waiter(t, s)).Wait(t.Context(), &pantherclawv1.WaitRequest{RunId: run, Handle: txn.String()}); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("another instance: %v", err)
	}
	ev, err := wc.SubmitEvidence(t.Context(), &pantherclawv1.SubmitEvidenceRequest{RunId: run, Handle: txn.String(), Note: "ticket 77"})
	if err != nil || ev.GetEvidenceId() == "" || ev.GetWait().GetState() != pantherclawv1.WaitState_WAIT_STATE_PENDING {
		t.Fatalf("evidence: %v, %v", ev, err)
	}
	denied := ids.NewV7()
	s.exec(t, o.org, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'DENY', 'TARGET_NOT_GRANTED', 'gw', 'OPEN')`, o.org, denied, run, ids.NewV7(), make([]byte, 32))
	acc, err := wc.RequestAccess(t.Context(), &pantherclawv1.WorkloadServiceRequestAccessRequest{RunId: run, TransactionId: denied.String(), Note: "need ch_2"})
	if err != nil || acc.GetEntryId() == "" || acc.GetDeadlineTime() == nil {
		t.Fatalf("access: %v, %v", acc, err)
	}
}
