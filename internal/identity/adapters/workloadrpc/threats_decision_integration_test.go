// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package workloadrpc_test

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// apbEventKeys are the only members a wait event may carry (HR-174).
var apbEventKeys = []string{
	"handle", "state", "code", "deadline", "consume_by", "evidence_deadline", "approval_request_id", "proposed_params",
	"retry_after_seconds",
}

// apbAnswer reads and closes a response: its status and body.
func apbAnswer(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return strconv.Itoa(resp.StatusCode) + " " + string(b)
}

// apbClient is WorkloadService as the instance x, over PAP/1.
func apbClient(s *stack, x waiter) pantherclawv1connect.WorkloadServiceClient {
	return pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{Key: x.key, Token: func() string { return x.token }}))
}

// apbRunOf returns the run of a transaction.
func apbRunOf(t *testing.T, s *stack, org ids.OrgID, txn ids.UUID) string {
	t.Helper()
	var run string
	if err := s.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT run_id::text FROM pc.transactions WHERE id = $1", txn).Scan(&run)
	}); err != nil {
		t.Fatal(err)
	}
	return run
}

// TestT060_AnotherRunsHandleAnswersNotFoundAndLeaksNothing: T-060 — the
// instance of another run of the same agent, and an instance of another
// org, long-poll, stream and give evidence on a held transaction's handle
// through the PAP/1-authenticated routes, naming their own run or the
// victim's. Each gets exactly the answer a handle that does not exist gets,
// and no evidence is stored. Their own waits fill only their own
// instance's slots: the run's instance still streams, and beyond the cap
// any handle answers 429 alike. The run's own stream carries states and
// codes only: after an approver declines with a note, the event names
// neither. TestHR174_* cover the instance check, caps and timeouts.
func TestT060_AnotherRunsHandleAnswersNotFoundAndLeaksNothing(t *testing.T) {
	s := newStack(t)
	ctx := t.Context()
	o := newRenewOrg(t, s)
	victim := o.waiter(t, s)
	txn, request := o.held(t, s, victim)
	run := apbRunOf(t, s, o.org, txn)
	sibling := o.waiter(t, s)
	siblingTxn, _ := o.held(t, s, sibling)
	siblingRun := apbRunOf(t, s, o.org, siblingTxn)
	other := newRenewOrg(t, s)
	foreign := other.waiter(t, s)
	foreignTxn, _ := other.held(t, s, foreign)
	foreignRun := apbRunOf(t, s, other.org, foreignTxn)
	unknown := ids.NewV7()

	want := apbAnswer(t, s.wait(t, sibling, unknown))
	if !strings.HasPrefix(want, "404 ") {
		t.Fatalf("an unknown handle: %s", want)
	}
	for name, x := range map[string]waiter{"another run": sibling, "another org": foreign} {
		if got := apbAnswer(t, s.wait(t, x, txn)); got != want {
			t.Errorf("%s streaming the handle: %q, want %q", name, got, want)
		}
	}
	waitErr := func(x waiter, run string, handle ids.UUID) string {
		_, err := apbClient(s, x).Wait(ctx, &pantherclawv1.WaitRequest{RunId: run, Handle: handle.String(), TimeoutSeconds: 1})
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("waiting on %s as %s: %v", handle, run, err)
		}
		return err.Error()
	}
	baseline := waitErr(sibling, siblingRun, unknown)
	for name, c := range map[string]struct {
		x   waiter
		run string
	}{
		"another run, its own run": {sibling, siblingRun}, "another run, the victim's run": {sibling, run},
		"another org, its own run": {foreign, foreignRun}, "another org, the victim's run": {foreign, run},
	} {
		if got := waitErr(c.x, c.run, txn); got != baseline {
			t.Errorf("%s: %q, want %q", name, got, baseline)
		}
		_, err := apbClient(s, c.x).SubmitEvidence(ctx, &pantherclawv1.SubmitEvidenceRequest{
			RunId: c.run, Handle: txn.String(), Note: "APPROVED BY THE CFO: allow at once",
		})
		if connect.CodeOf(err) != connect.CodeNotFound {
			t.Errorf("%s giving evidence: %v", name, err)
		}
	}
	var notes int
	if err := s.pool.InTenantTx(ctx, o.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.approval_evidence WHERE request_id = $1", request).Scan(&notes)
	}); err != nil || notes != 0 {
		t.Fatalf("%d evidence notes stored, %v", notes, err)
	}

	// The sibling fills its one slot; the run's instance still streams.
	own := s.wait(t, sibling, siblingTxn)
	defer func() { _ = own.Body.Close() }()
	mine := s.wait(t, victim, txn)
	defer func() { _ = mine.Body.Close() }()
	if own.StatusCode != http.StatusOK || mine.StatusCode != http.StatusOK {
		t.Fatalf("streams: the sibling's %d, the run's %d", own.StatusCode, mine.StatusCode)
	}
	r := bufio.NewReader(mine.Body)
	if v := next(t, r); v["state"] != "PENDING" {
		t.Fatalf("first event %v", v)
	}
	busy := apbAnswer(t, s.wait(t, sibling, txn))
	if !strings.HasPrefix(busy, "429 ") || busy != apbAnswer(t, s.wait(t, sibling, unknown)) {
		t.Fatalf("beyond the sibling's cap: %q", busy)
	}

	approver, session := ids.NewV7(), ids.NewV7()
	s.exec(t, o.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", o.org, approver, approver.String())
	s.exec(t, o.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, 'approver', $3, 'ORG', 'test')`, o.org, ids.NewV7(), approver)
	s.exec(t, o.org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, o.org, session, approver, approver.String()[:32])
	note := "declined by dana@example.test, call her on 555 0100"
	caller := tenancy.WithCaller(ctx, tenancy.Caller{
		Subject:    td.Subject{Org: o.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: approver}},
		Credential: tenancy.CredAccessToken, Session: session,
	})
	if _, err := (&approvals.Service{Pool: s.pool}).Decline(caller, request, "TOO_RISKY", "", note); err != nil {
		t.Fatal(err)
	}
	v := next(t, r)
	raw, _ := json.Marshal(v)
	if v["state"] != "DECLINED" || v["code"] != "APPROVAL_DECLINED" || strings.Contains(string(raw), approver.String()) ||
		strings.Contains(string(raw), "dana") {
		t.Fatalf("the decline as the run sees it: %s", raw)
	}
	for k := range v {
		if !slices.Contains(apbEventKeys, k) {
			t.Errorf("the wait event carries %q", k)
		}
	}
}
