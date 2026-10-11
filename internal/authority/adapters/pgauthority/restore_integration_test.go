// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// approvedAction holds an $85 refund, has bob approve it and resubmits:
// the resubmission's permit consumes the approval.
func (w *world) approvedAction() (finalize.Result, ids.UUID, func() finalize.Result) {
	w.t.Helper()
	w.refundable("ch_1")
	g := w.heldGrant()
	req := w.request(w.run(g.ID, ids.UUID{}), ids.NewV7(), "ch_1", "85.00")
	request := held(w.t.(*testing.T), w.authorize(req))
	w.approve(request)
	resubmit := func() finalize.Result { return w.authorize(req) }
	r := resubmit()
	if r.Decision != adomain.Allow || r.Permit == "" {
		w.t.Fatalf("the approved resubmission: %s %s", r.Decision, decisive(r))
	}
	if s := w.str("SELECT state || '/' || permit_id::text FROM pc.approval_requests WHERE id = $1", request); s != "CONSUMED/"+r.PermitID.String() {
		w.t.Fatalf("request %s", s)
	}
	return r, request, resubmit
}

// permitApproval decodes a permit's pap.approval (HR-038).
func permitApproval(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Pap struct {
			Approval map[string]any `json:"approval"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(b, &c, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	return c.Pap.Approval
}

// restored checks that request is APPROVED again, without its permit, and
// its transaction open for the resubmission.
func (w *world) restored(request, txn ids.UUID) {
	w.t.Helper()
	if s := w.str("SELECT state || '/' || (permit_id IS NULL)::text || '/' || (consumed_at IS NULL)::text || '/' || (ended_at IS NULL)::text"+
		" FROM pc.approval_requests WHERE id = $1", request); s != "APPROVED/true/true/true" {
		w.t.Fatalf("request after the release: %s", s)
	}
	if s := w.str("SELECT state FROM pc.transactions WHERE id = $1", txn); s != "OPEN" {
		w.t.Fatalf("transaction after the restore: %s", s)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.approval.restored'"); n != 1 {
		w.t.Fatalf("%d approval.restored events", n)
	}
	if n := w.count("SELECT coalesce(sum(pending), 0)::int FROM pc.hold_slots"); n != 2 {
		w.t.Fatalf("hold slots %d, want the grant's and the run's taken again", n)
	}
}

// usedOnce dispatches the resubmission's permit, which consumes the
// restored approval, and checks that a further resubmission gets the
// stored decision and no permit (HR-005).
func (w *world) usedOnce(resubmit func() finalize.Result, request, old ids.UUID) {
	w.t.Helper()
	ctx := context.Background()
	r := resubmit()
	if r.Decision != adomain.Allow || r.Permit == "" || r.PermitID == old {
		w.t.Fatalf("the resubmission after the restore: %s %s, permit %s", r.Decision, decisive(r), r.PermitID)
	}
	if s := w.str("SELECT state || '/' || permit_id::text FROM pc.approval_requests WHERE id = $1", request); s != "CONSUMED/"+r.PermitID.String() {
		w.t.Fatalf("request after its second use %s", s)
	}
	if s := w.str("SELECT string_agg(state || '/' || replaced::text, ',' ORDER BY issued_at) FROM pc.permits WHERE transaction_id = $1",
		r.TransactionID); s != "RELEASED/true,ISSUED/false" {
		w.t.Fatalf("the transaction's permits: %s", s)
	}
	if _, err := w.auth.BeginDispatch(ctx, w.gw, r.PermitID, r.Epoch, finalize.Outbound{}); err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Accepted, DispatchMS: -1}); err != nil {
		w.t.Fatal(err)
	}
	if again := resubmit(); again.Permit != "" || !again.Repeat {
		w.t.Fatalf("a restored approval was used twice: %s %s", again.Decision, decisive(again))
	}
}

// TestHR011_AnApprovalIsRestoredWhenItsPermitExpiredUnused: the permit of
// an approved refund carries the approval (HR-038) and expires ISSUED;
// the sweeper releases it, restores the approval and reopens the
// transaction, so the agent's resubmission of the same run and action
// gets a new permit that uses the approval, once.
func TestHR011_AnApprovalIsRestoredWhenItsPermitExpiredUnused(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Second
	first, request, resubmit := w.approvedAction()
	a := permitApproval(t, first.Permit)
	if as, _ := a["assertions"].([]any); a["binding"] == nil || a["input"] == nil || len(as) != 1 {
		t.Fatalf("the permit's approval %v", a)
	}
	w.waitExpired(first.PermitID)
	if released, _, err := w.auth.Sweep(context.Background(), w.org, time.Minute); err != nil || released != 1 {
		t.Fatalf("sweep: %d released: %v", released, err)
	}
	w.restored(request, first.TransactionID)
	w.auth.PermitTTL = time.Hour
	w.usedOnce(resubmit, request, first.PermitID)
}

// TestHR011_AnApprovalIsRestoredWhenBeginDispatchRefusedItsPermit: a
// containment change between Authorize and BeginDispatch makes the permit
// unusable; the refusal releases it and restores the approval at once.
func TestHR011_AnApprovalIsRestoredWhenBeginDispatchRefusedItsPermit(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	first, request, resubmit := w.approvedAction()
	w.db.AdminExec(t, "UPDATE pc.org_containment SET epoch = epoch + 1 WHERE org_id = $1", w.org)
	_, err := w.auth.BeginDispatch(context.Background(), w.gw, first.PermitID, first.Epoch, finalize.Outbound{})
	if !errors.Is(err, finalize.ErrEpochStale) {
		t.Fatalf("BeginDispatch with a stale epoch: %v", err)
	}
	if s := w.str("SELECT state FROM pc.permits WHERE id = $1", first.PermitID); s != "RELEASED" {
		t.Fatalf("the refused permit is %s", s)
	}
	w.restored(request, first.TransactionID)
	w.usedOnce(resubmit, request, first.PermitID)
}

// TestHR011_NothingIsRestoredAfterBeginDispatch: once a permit reached
// DISPATCHING something may have been sent, so a failed, unknown or stale
// dispatch leaves the approval used and the transaction final.
func TestHR011_NothingIsRestoredAfterBeginDispatch(t *testing.T) {
	for name, settle := range map[string]func(w *world, r finalize.Result){
		"failed": func(w *world, r finalize.Result) {
			if _, err := w.auth.RecordExecution(context.Background(), w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Failed, DispatchMS: -1}); err != nil {
				t.Fatal(err)
			}
		},
		"unknown": func(w *world, r finalize.Result) {
			if _, err := w.auth.RecordExecution(context.Background(), w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Unknown, DispatchMS: -1}); err != nil {
				t.Fatal(err)
			}
		},
		"stale dispatching": func(w *world, r finalize.Result) {
			w.db.AdminExec(t, "UPDATE pc.permits SET expires_at = now() - interval '1 second' WHERE id = $1", r.PermitID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.auth.PermitTTL = time.Hour
			first, request, resubmit := w.approvedAction()
			if _, err := w.auth.BeginDispatch(context.Background(), w.gw, first.PermitID, first.Epoch, finalize.Outbound{}); err != nil {
				t.Fatal(err)
			}
			settle(w, first)
			if _, _, err := w.auth.Sweep(context.Background(), w.org, time.Nanosecond); err != nil {
				t.Fatal(err)
			}
			if s := w.str("SELECT state || '/' || permit_id::text FROM pc.approval_requests WHERE id = $1", request); s != "CONSUMED/"+first.PermitID.String() {
				t.Fatalf("the approval after a dispatch: %s", s)
			}
			if s := w.str("SELECT state FROM pc.transactions WHERE id = $1", first.TransactionID); s != "FINAL" {
				t.Fatalf("the transaction after a dispatch: %s", s)
			}
			if again := resubmit(); again.Permit != "" {
				t.Fatalf("a resubmission after a dispatch got a permit: %s %s", again.Decision, decisive(again))
			}
			if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.approval.restored'"); n != 0 {
				t.Fatalf("%d approval.restored events", n)
			}
		})
	}
}

// TestHR011_AnExpiredPermitWithoutAnApprovalStaysFinal: only an approval
// restore reopens a transaction; a plain ALLOW whose permit expired is
// still answered from storage (HR-005, HR-006).
func TestHR011_AnExpiredPermitWithoutAnApprovalStaysFinal(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	w.auth.PermitTTL = time.Millisecond
	req := w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00")
	r := w.authorize(req)
	w.waitExpired(r.PermitID)
	if released, _, err := w.auth.Sweep(context.Background(), w.org, time.Minute); err != nil || released != 1 {
		t.Fatalf("sweep: %d: %v", released, err)
	}
	if s := w.str("SELECT state FROM pc.transactions WHERE id = $1", r.TransactionID); s != "FINAL" {
		t.Fatalf("transaction %s", s)
	}
	if again := w.authorize(req); again.Permit != "" || !again.Repeat {
		t.Fatalf("an expired ALLOW gave a second permit: %s %s", again.Decision, decisive(again))
	}
}
