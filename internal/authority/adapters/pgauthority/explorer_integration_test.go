// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// reader is a person bound to role at scope.
func (w *world) reader(role tdomain.RoleName, scope tdomain.Scope) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: tdomain.Subject{
			Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: ids.NewV7()},
			Bindings: []tdomain.Binding{{Role: role, Scope: scope}},
		},
		Credential: tapp.CredAccessToken,
	})
}

// TestExplorer_ListsByExecutionStateAndScope: the list's execution-state
// filter (SQL) agrees with the derived state (domain.Execution) for every
// transaction, and a caller without evidence.read where the agent lives
// sees nothing (F471–F479).
func TestExplorer_ListsByExecutionStateAndScope(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4", "ch_5", "ch_6")
	run := w.run(w.grant("500").ID, ids.UUID{})
	want := map[txdomain.ExecutionState]ids.UUID{}
	want[txdomain.Authorized] = w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00")).TransactionID
	want[txdomain.Dispatched] = w.dispatched(run, "ch_2", "10.00").TransactionID
	want[txdomain.Accepted] = w.recorded(run, "ch_3", "10.00", finalize.Accepted, "").TransactionID
	failed := w.dispatched(run, "ch_4", "10.00")
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: failed.PermitID, Outcome: finalize.Failed, TargetStatus: 402, DispatchMS: 1}); err != nil {
		t.Fatal(err)
	}
	want[txdomain.Failed] = failed.TransactionID
	blocked := w.authorize(w.request(run, ids.NewV7(), "ch_5", "150.00"))
	if blocked.Permit != "" {
		t.Fatalf("over the bound: %s", blocked.Decision)
	}
	want[txdomain.Blocked] = blocked.TransactionID
	held := w.authorize(w.request(w.run(w.heldGrant().ID, ids.UUID{}), ids.NewV7(), "ch_6", "60.00"))
	want[txdomain.Waiting] = held.TransactionID

	auditor := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()})
	e := &txapp.Explorer{Pool: w.pool}
	all, err := e.ListTransactions(auditor, page.Request{Size: 50}, txapp.Filter{})
	if err != nil || len(all.Items) != len(want) {
		t.Fatalf("all: %d %v", len(all.Items), err)
	}
	if !slices.IsSortedFunc(all.Items, func(a, b txapp.Summary) int { return -compareIDs(a.ID, b.ID) }) {
		t.Fatal("not newest first")
	}
	for _, s := range []txdomain.ExecutionState{
		txdomain.Requested, txdomain.Blocked, txdomain.Waiting, txdomain.Authorized, txdomain.Dispatched,
		txdomain.Accepted, txdomain.Failed, txdomain.Canceled,
	} {
		p, err := e.ListTransactions(auditor, page.Request{Size: 50}, txapp.Filter{Executions: []txdomain.ExecutionState{s}})
		if err != nil {
			t.Fatal(err)
		}
		id, ok := want[s]
		if !ok {
			if len(p.Items) != 0 {
				t.Fatalf("%s: %d transactions, want none", s, len(p.Items))
			}
			continue
		}
		if len(p.Items) != 1 || p.Items[0].ID != id || p.Items[0].Execution != s {
			t.Fatalf("%s: %+v, want only %s", s, p.Items, id)
		}
	}
	if p, _ := e.ListTransactions(auditor, page.Request{Size: 50}, txapp.Filter{Decisions: []string{"REQUIRE_APPROVAL"}}); len(p.Items) != 1 || p.Items[0].ID != held.TransactionID {
		t.Fatalf("by decision: %+v", p.Items)
	}
	if p, _ := e.ListTransactions(auditor, page.Request{Size: 2}, txapp.Filter{Run: &run}); len(p.Items) != 2 || p.Next == "" {
		t.Fatalf("first page of the run's: %d %q", len(p.Items), p.Next)
	}

	elsewhere := w.reader(tdomain.RoleDeveloper, tdomain.Scope{Type: tdomain.ScopeTeam, ID: ids.NewV7()})
	if p, err := e.ListTransactions(elsewhere, page.Request{Size: 50}, txapp.Filter{}); err != nil || len(p.Items) != 0 {
		t.Fatalf("another team's developer sees %d: %v", len(p.Items), err)
	}
	if _, err := e.TransactionEvidence(elsewhere, held.TransactionID); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("another team's developer reads the evidence: %v", err)
	}
	if _, err := e.TransactionEvidence(auditor, ids.NewV7()); !errors.Is(err, txapp.ErrTransactionNotFound) {
		t.Fatalf("an unknown transaction: %v", err)
	}
}

// TestExplorer_ShowsEveryRecordOfAnUnknownRefund: the explorer returns the
// decision receipt and its basis, the execution receipt, the observation,
// the effect receipts and the reconciliation, each with its ledger entry.
func TestExplorer_ShowsEveryRecordOfAnUnknownRefund(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	r := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	l := w.lease(s, r.TransactionID)
	if _, err := s.Report(ctx, w.org, w.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Complete: true,
		Fields: refund("succeeded", "30.00"),
	}); err != nil {
		t.Fatal(err)
	}

	e := &txapp.Explorer{Pool: w.pool}
	ev, err := e.TransactionEvidence(w.reader(tdomain.RoleReconciler, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}), r.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Transaction.Execution != txdomain.Dispatched || ev.Transaction.Effect != txdomain.Confirmed || ev.Transaction.Achieved != "follow_up" {
		t.Fatalf("transaction %+v", ev.Transaction)
	}
	if len(ev.Decisions) != 1 || ev.Decisions[0].JWS == "" || ev.Decisions[0].Integrity.Entry.IsZero() {
		t.Fatalf("decisions %+v", ev.Decisions)
	}
	if ev.Basis == nil || ev.Basis.Definition == "" || ev.Basis.Digest == "" || len(ev.Basis.Levels) == 0 || ev.Basis.Connection != w.conn.String() {
		t.Fatalf("basis %+v", ev.Basis)
	}
	if x := ev.Execution; x == nil || x.Outcome != "unknown" || x.RecordedBy != "gateway" || x.JWS == "" || x.Dispatched == nil {
		t.Fatalf("execution %+v", ev.Execution)
	}
	if len(ev.Observations) != 1 || ev.Observations[0].Fields["/status"] != "succeeded" || ev.Observations[0].Found == nil || !*ev.Observations[0].Found {
		t.Fatalf("observations %+v", ev.Observations)
	}
	if n := len(ev.Effects); n == 0 || ev.Effects[n-1].State != txdomain.Confirmed || ev.Effects[n-1].Basis != "verifier" {
		t.Fatalf("effects %+v", ev.Effects)
	}
	if len(ev.Reconciliations) != 1 || ev.Reconciliations[0].State != txdomain.TaskOccurred || ev.Reconciliations[0].Via != txdomain.ViaVerifier ||
		ev.Reconciliations[0].Observation == nil || *ev.Reconciliations[0].Observation != ev.Observations[0].ID {
		t.Fatalf("reconciliations %+v", ev.Reconciliations)
	}
}

// TestExplorer_ReportsEachItemsIntegrity: each receipt's integrity is
// pending until the chainer links its entry, then chained, in a checkpoint
// once a signed checkpoint's tree covers it (naming the first such
// checkpoint), and anchored once an ANCHORED anchor covers such a
// checkpoint; a pending or failed anchor does not count (F466–F468,
// HR-194, HR-195). The checkpoint and anchor rows are seeded here: their
// jobs are tested with track B.
func TestExplorer_ReportsEachItemsIntegrity(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	r := w.recorded(run, "ch_1", "30.00", finalize.Accepted, "re_1")
	e := &txapp.Explorer{Pool: w.pool}
	reader := w.reader(tdomain.RoleReconciler, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()})
	statuses := func() (txapp.Integrity, txapp.Integrity) {
		t.Helper()
		ev, err := e.TransactionEvidence(reader, r.TransactionID)
		if err != nil || len(ev.Decisions) != 1 || ev.Execution == nil {
			t.Fatalf("evidence %+v: %v", ev, err)
		}
		return ev.Decisions[0].Integrity, ev.Execution.Integrity
	}
	if d, x := statuses(); d.Status() != txapp.IntegrityPending || x.Status() != txapp.IntegrityPending {
		t.Fatalf("before chaining: %+v %+v", d, x)
	}
	if _, err := ledger.ChainAll(context.Background(), w.pool, w.org, 500); err != nil {
		t.Fatal(err)
	}
	d, x := statuses()
	if d.Status() != txapp.IntegrityChained || x.Status() != txapp.IntegrityChained || d.Seq >= x.Seq {
		t.Fatalf("chained: %+v %+v", d, x)
	}

	checkpoint := func(size int64) {
		w.db.AdminExec(t, `INSERT INTO pc.checkpoints (org_id, tree_size, root_hash, note, kid) VALUES ($1, $2, $3, $4, 'test-checkpoints')`,
			w.org, size, make([]byte, 32), []byte(strings.Repeat("n", 64)))
	}
	anchor := func(size int64, state string) {
		id := ids.NewV7()
		period := time.Now().Add(time.Duration(size) * time.Hour)
		if state == "ANCHORED" {
			w.db.AdminExec(t, `INSERT INTO pc.anchors (id, period, leaves, root, statement, signature, kid, state, rekor_entry, timestamp_token, anchored_at)
				VALUES ($1, $2, $3, $3, '{}', $4, 'test-anchors', 'ANCHORED', '{}', $5, now())`, id, period, make([]byte, 32), make([]byte, 8), []byte{1})
		} else {
			w.db.AdminExec(t, `INSERT INTO pc.anchors (id, period, leaves, root, statement, signature, kid, state)
				VALUES ($1, $2, $3, $3, '{}', $4, 'test-anchors', $5)`, id, period, make([]byte, 32), make([]byte, 8), state)
		}
		w.db.AdminExec(t, `INSERT INTO pc.anchor_leaves (org_id, anchor_id, leaf_index, nonce, checkpoint_size) VALUES ($1, $2, 0, $3, $4)`,
			w.org, id, make([]byte, 32), size)
	}

	checkpoint(d.Seq)
	anchor(d.Seq, "PENDING")
	anchor(d.Seq, "FAILED")
	if d, x := statuses(); d.Status() != txapp.IntegrityCheckpointed || d.Checkpoint != d.Seq || x.Status() != txapp.IntegrityChained {
		t.Fatalf("one checkpoint, anchors not done: %+v %+v", d, x)
	}
	checkpoint(x.Seq)
	anchor(d.Seq, "ANCHORED")
	d2, x2 := statuses()
	if d2.Status() != txapp.IntegrityAnchored || d2.Checkpoint != d.Seq || d2.Anchored != d.Seq || d2.AnchoredAt == nil {
		t.Fatalf("the decision's checkpoint anchored: %+v", d2)
	}
	if x2.Status() != txapp.IntegrityCheckpointed || x2.Checkpoint != x.Seq || x2.Anchored != 0 {
		t.Fatalf("the execution's checkpoint not anchored: %+v", x2)
	}
	anchor(x.Seq, "ANCHORED")
	if _, x3 := statuses(); x3.Status() != txapp.IntegrityAnchored || x3.Anchored != x.Seq {
		t.Fatalf("both anchored: %+v", x3)
	}
}

func compareIDs(a, b ids.UUID) int {
	return slices.Compare(a[:], b[:])
}
