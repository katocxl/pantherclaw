// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Threat-level scenarios of G0 M7 (T-070..T-074) through the real
// services, for the parts of each threat the HR tests do not already tell.

// m7OtherOrg adds a second org to the world's database, with its
// containment row and a gateway of its own.
func (w *world) m7OtherOrg(name string) (ids.OrgID, ids.UUID) {
	w.t.Helper()
	org, gw := ids.New[ids.Org](), ids.NewV7()
	exec(w.t, w.pool, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", org, name)
	if err := w.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, org)
	}); err != nil {
		w.t.Fatal(err)
	}
	exec(w.t, w.pool, org, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", org, gw)
	return org, gw
}

// m7Admin counts rows as the admin, across every org.
func (w *world) m7Admin(sql string, args ...any) int {
	w.t.Helper()
	var n int
	w.db.AdminQueryRow(w.t, sql, args, &n)
	return n
}

// m7Parked checks that an identical refund, from a new action id, is
// parked for reconciliation rather than permitted (HR-007).
func (w *world) m7Parked(run ids.UUID, charge, amount, when string) {
	w.t.Helper()
	if r := w.authorize(w.request(run, ids.NewV7(), charge, amount)); r.Permit != "" || decisive(r) != pipeline.ReasonReconciliation {
		w.t.Fatalf("%s: an identical refund got %s, permit %q (%s)", when, r.Decision, r.Permit, decisive(r))
	}
}

// TestT070_AStolenLeaseIsWorthlessToAnotherOrgsGateway: a gateway of
// another org that got hold of a task id and its lease secret (a leaked
// log line, a compromised host) tries to report a forged observation with
// them, naming its own gateway or the victim's. Its org comes from its
// certificate, so the task does not exist for it: the report is refused,
// nothing is observed and no effect receipt is written. It cannot lease the
// victim's tasks either. The lease is not used up: the gateway that made
// the read still reports it, once (HR-190, design decision 18).
func TestT070_AStolenLeaseIsWorthlessToAnotherOrgsGateway(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	r := w.recorded(w.run(w.grant("500").ID, ids.UUID{}), "ch_1", "30.00", finalize.Accepted, "re_1")
	other, otherGW := w.m7OtherOrg("globex")
	names := map[string]ids.UUID{"its own gateway": otherGW, "the victim's gateway id": w.gwID}

	for name, gw := range names {
		if l, err := s.Claim(ctx, other, gw, 16); err != nil || len(l) != 0 {
			t.Fatalf("another org leased %d tasks naming %s: %v", len(l), name, err)
		}
	}
	l := w.lease(s, r.TransactionID)
	forged := txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refundOf("ch_1", "succeeded", "30.00")}
	for name, gw := range names {
		if _, err := s.Report(ctx, other, gw, forged); !errors.Is(err, txapp.ErrLease) {
			t.Errorf("a stolen lease reported naming %s: %v, want ErrLease", name, err)
		}
	}
	if n := w.m7Admin("SELECT count(*) FROM pc.observations"); n != 0 {
		t.Fatalf("%d observations recorded from a stolen lease", n)
	}
	if n := w.m7Admin("SELECT count(*) FROM pc.effect_receipts"); n != 0 {
		t.Fatalf("%d effect receipts written from a stolen lease", n)
	}
	a, err := s.Report(ctx, w.org, w.gwID, forged)
	if err != nil || a.State != txdomain.Confirmed {
		t.Fatalf("the gateway that read: %+v %v", a, err)
	}
	if n := w.m7Admin("SELECT count(*) FROM pc.observations WHERE org_id = $1 AND gateway_id = $2", w.org, w.gwID); n != 1 {
		t.Fatalf("%d observations by the gateway that read", n)
	}
}

// TestT071_ALaterConfirmationDoesNotCollapseAConflict: the target accepted
// a 30.00 refund and the verifier's read found it recorded at 29.99. The
// effect is CONFLICTING and a person must say which observation is
// authoritative. A second read, asked for later, finds 30.00 and is
// appended as CONFIRMED beside the conflict; it neither rewrites the
// CONFLICTING receipt, drops the first observation nor closes the conflict
// by itself, and the budget the acceptance committed is committed once
// (HR-191, F484, F498).
func TestT071_ALaterConfirmationDoesNotCollapseAConflict(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	r := w.recorded(w.run(w.grant("500").ID, ids.UUID{}), "ch_1", "30.00", finalize.Accepted, "re_1")
	report := func(amount string) txapp.Applied {
		t.Helper()
		l := w.lease(s, r.TransactionID)
		a, err := s.Report(ctx, w.org, w.gwID, txapp.Report{
			Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refundOf("ch_1", "succeeded", amount),
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if a := report("29.99"); a.State != txdomain.Conflicting || !a.Done {
		t.Fatalf("the short refund: %+v", a)
	}
	conflict := w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 AND state = 'CONFLICTING'", r.TransactionID)
	task, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'conflicting_effect' AND state = 'OPEN'",
		r.TransactionID))
	if err != nil {
		t.Fatal(err)
	}

	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	person, _ := w.reconciler("rita")
	if _, err := rec.RequestVerification(person, r.TransactionID); err != nil {
		t.Fatal(err)
	}
	w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", r.TransactionID)
	if a := report("30.00"); a.State != txdomain.Confirmed || a.Resolved {
		t.Fatalf("the later read: %+v", a)
	}

	if got := w.str("SELECT string_agg(state || '/' || basis, ',' ORDER BY seq) FROM pc.effect_receipts WHERE transaction_id = $1", r.TransactionID); got != "CONFLICTING/verifier,CONFIRMED/verifier" {
		t.Fatalf("effect receipts %s, want the conflict kept beside the confirmation", got)
	}
	if w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 AND state = 'CONFLICTING'", r.TransactionID) != conflict {
		t.Fatal("the CONFLICTING receipt was rewritten")
	}
	if got := w.str("SELECT string_agg(fields->>'/amount', ',' ORDER BY observed_at, id) FROM pc.observations WHERE transaction_id = $1", r.TransactionID); got != "29.99,30.00" {
		t.Fatalf("observed amounts %s, want both sides", got)
	}
	if got := w.str("SELECT state FROM pc.reconciliation_tasks WHERE id = $1", task); got != "OPEN" {
		t.Fatalf("a later read closed the conflict by itself: %s", got)
	}
	if res, sp := w.budget(); res != "0" || sp != "30" {
		t.Fatalf("reserved %s spent %s, want 30 committed once", res, sp)
	}
	e := &txapp.Explorer{Pool: w.pool}
	open, err := e.ListReconciliations(person, page.Request{Size: 50}, txapp.ReconciliationFilter{States: []txdomain.TaskState{txdomain.TaskOpen}})
	if err != nil || len(open.Items) != 1 || open.Items[0].ID != task || open.Items[0].Kind != txdomain.KindConflictingEffect {
		t.Fatalf("open reconciliations %+v %v", open.Items, err)
	}
	ev, err := e.TransactionEvidence(person, r.TransactionID)
	if err != nil || len(ev.Observations) != 2 || len(ev.Effects) != 2 {
		t.Fatalf("the explorer shows %d observations and %d effects: %v", len(ev.Observations), len(ev.Effects), err)
	}
}

// TestT072_ACompensationNeverResolvesAnUnknownRefund: a 30.00 refund to
// ch_1 hung and its outcome is UNKNOWN. To make the incident look handled
// and get the 30.00 back, a separate refund is authorized, confirmed by the
// verifier and linked as the compensation of the unknown one. The link is
// recorded, but the unknown refund keeps its open reconciliation, its held
// reservation and dedupe claim and its records, gains no COMPENSATED
// receipt (only a confirmed effect is compensated), and an identical refund
// to ch_1 is still parked (HR-193, HR-192, HR-007).
func TestT072_ACompensationNeverResolvesAnUnknownRefund(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	unknown := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	comp := w.recorded(run, "ch_2", "10.00", finalize.Accepted, "re_2")
	records := func() string {
		return w.str(`SELECT (SELECT string_agg(receipt_jws, ',' ORDER BY evaluation) FROM pc.decision_receipts WHERE transaction_id = $1)
			|| (SELECT receipt_jws FROM pc.execution_receipts WHERE transaction_id = $1)
			|| (SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1)::text`, unknown.TransactionID)
	}
	before := records()

	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	person, _ := w.reconciler("rita")
	if _, err := rec.Link(person, txapp.LinkRequest{From: comp.TransactionID, To: unknown.TransactionID, Kind: txdomain.LinkCompensates}); err != nil {
		t.Fatalf("link: %v", err)
	}
	w.confirm(s, comp.TransactionID, "ch_2", "10.00")

	if records() != before {
		t.Fatal("the unknown refund's records changed")
	}
	if got := w.str(`SELECT (SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'unknown_outcome') || ' ' ||
		(SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1) || ' ' ||
		(SELECT string_agg(DISTINCT state, ',') FROM pc.reservations WHERE transaction_id = $1) || ' ' ||
		coalesce((SELECT effect_state FROM pc.transactions WHERE id = $1), 'none')`, unknown.TransactionID); got != "OPEN HELD HELD none" {
		t.Fatalf("task, claim, reservations and effect: %s, want OPEN HELD HELD none", got)
	}
	if res, sp := w.budget(); res != "30" || sp != "10" {
		t.Fatalf("reserved %s spent %s, want the unknown 30 held and the compensation's 10 spent", res, sp)
	}
	w.m7Parked(run, "ch_1", "30.00", "after the compensation")
	ev, err := (&txapp.Explorer{Pool: w.pool}).TransactionEvidence(person, unknown.TransactionID)
	if err != nil || ev.Transaction.Effect != "" || len(ev.Links) != 1 || len(ev.Reconciliations) != 1 || ev.Reconciliations[0].State != txdomain.TaskOpen {
		t.Fatalf("the explorer shows effect %q, %d links, reconciliations %+v: %v", ev.Transaction.Effect, len(ev.Links), ev.Reconciliations, err)
	}
}

// TestT072_TheAgentsOwnerCannotFreeItsUnknownRefund: alice owns the refund
// agent, launched its run and is the principal it acts for. Its 30.00
// refund hung, and she wants the budget back to send it again. She holds
// Reconciler, but releasing ("did not occur") is no API call: it is the
// security-key page, for an independent person (design decision 3). The
// one resolution she can make, "occurred", commits the 30.00 instead of
// freeing it, sets the claim SUCCEEDED, names her in the effect receipt and
// the ledger, and the identical refund stays parked for the repeat window
// (HR-192, HR-003, HR-007).
func TestT072_TheAgentsOwnerCannotFreeItsUnknownRefund(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	r := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	if got := w.str("SELECT owner_user_id::text || launcher_user_id::text || principal_user_id::text FROM pc.runs r JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id WHERE r.id = $1",
		run); got != w.alice.String()+w.alice.String()+w.alice.String() {
		t.Fatalf("alice is not the agent's owner, the run's launcher and its principal: %s", got)
	}
	owner := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: tdomain.Subject{
			Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: w.alice},
			Bindings: []tdomain.Binding{{Role: tdomain.RoleReconciler, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}}},
		},
		Credential: tapp.CredAccessToken,
	})
	task, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	w.m7Parked(run, "ch_1", "30.00", "while unknown")

	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	k, err := rec.ResolveOccurred(owner, txapp.Resolution{Reconciliation: task, Basis: "I think it went through; let me retry it."})
	if err != nil || k.State != txdomain.TaskOccurred || k.User == nil || *k.User != w.alice {
		t.Fatalf("resolved %+v %v", k, err)
	}
	if res, sp := w.budget(); res != "0" || sp != "30" {
		t.Fatalf("reserved %s spent %s: her resolution must commit the 30.00, never free it", res, sp)
	}
	if got := w.str("SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1", r.TransactionID); got != "SUCCEEDED" {
		t.Fatalf("claim %s", got)
	}
	pap := claims(t, w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID))
	if b, _ := pap["basis"].(map[string]any); pap["state"] != "CONFIRMED" || b["kind"] != "person" || b["person"] != w.alice.String() {
		t.Fatalf("effect receipt %v", pap)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.transaction.reconciliation_resolved' AND actor_id = $1", w.alice.String()); n != 1 {
		t.Fatalf("%d resolutions in the ledger by her", n)
	}
	w.m7Parked(run, "ch_1", "30.00", "after her resolution")
}

// TestT074_ReplayCannotProbeAnotherOrgsPolicy: a person replays their own
// org's decision under a draft policy version of another org, to learn what
// that org's rules would decide. The version does not exist in their org,
// so the replay is refused as not found and returns nothing; the other org
// cannot replay this org's decision either (T-037). Their own draft replays,
// as the control.
func TestT074_ReplayCannotProbeAnotherOrgsPolicy(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.keepInputs()
	w.refundable("ch_1")
	w.publishPolicy(1, false, pgHoldOver50)
	r := w.authorize(w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "30.00"))
	other, _ := w.m7OtherOrg("globex")
	theirs, _, err := (&polpg.Store{Pool: w.pool}).CreateVersion(ctx, other, &pdomain.Bundle{ID: "org-policy", Rules: []pdomain.Rule{pgForbidOver20}},
		ids.NewV7().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := w.replayEngine()
	if out, err := engine.Replay(ctx, w.org, r.TransactionID, r.Evaluation, &theirs); !errors.Is(err, replay.ErrNotFound) {
		t.Fatalf("another org's draft replayed: %+v %v", out, err)
	}
	if out, err := engine.Replay(ctx, other, r.TransactionID, r.Evaluation, &theirs); !errors.Is(err, replay.ErrNotFound) {
		t.Fatalf("another org replayed this org's decision: %+v %v", out, err)
	}
	ours := w.publishPolicy(2, true, pgHoldOver50, pgForbidOver20)
	if out, err := engine.Replay(ctx, w.org, r.TransactionID, r.Evaluation, &ours); err != nil || out.Reason != "REFUND_TOO_LARGE" {
		t.Fatalf("the org's own draft: %+v %v", out, err)
	}
}
