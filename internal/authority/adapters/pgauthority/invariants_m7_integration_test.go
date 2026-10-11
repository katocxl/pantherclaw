// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// The M7 parts of invariants 9 and 11 (ARCHITECTURE §1, G0 M7 tests):
// reconciliation and effects live in PostgreSQL only, so they are shown
// here on the real stores rather than on the in-memory world of
// test/invariants.

// m7Observation is one thing a verifier read may report for a refund whose
// expected fields are want, and whether it shows that the refund happened
// (domain.Assessment.Occurred).
type m7Observation struct {
	name     string
	report   func(want map[string]string) txapp.Report
	occurred bool
}

// m7Found is a read that found the refund with status, and with field
// changed to value when field is set.
func m7Found(status, field, value string) func(map[string]string) txapp.Report {
	return func(want map[string]string) txapp.Report {
		f := map[string]string{"/status": status}
		for k, v := range want {
			f[k] = v
		}
		if field != "" {
			f[field] = value
		}
		return txapp.Report{HTTPStatus: 200, Found: true, Complete: true, Fields: f}
	}
}

func m7Plain(status int, complete bool) func(map[string]string) txapp.Report {
	return func(map[string]string) txapp.Report { return txapp.Report{HTTPStatus: status, Complete: complete} }
}

var m7Observations = []m7Observation{
	{"a read that failed", m7Plain(0, false), false},
	{"a server error", m7Plain(503, false), false},
	{"a refused read", m7Plain(401, false), false},
	{"not found", m7Plain(404, false), false},
	{"a listing cut short", m7Plain(200, false), false},
	{"absent from a complete listing", m7Plain(200, true), false},
	{"found and settled", m7Found("succeeded", "", ""), true},
	{"found and pending", m7Found("pending", "", ""), true},
	{"found with an unreviewed status", m7Found("on_hold", "", ""), true},
	{"found and failed at the target", m7Found("failed", "", ""), false},
	{"found and canceled", m7Found("canceled", "", ""), false},
	{"found with another amount", m7Found("succeeded", "/amount", "99.99"), false},
	{"found on another charge", m7Found("succeeded", "/charge", "ch_other"), false},
}

// m7TryLease leases txn's due verification, if it has one.
func (w *world) m7TryLease(s *txapp.Service, txn ids.UUID) (txapp.Lease, bool) {
	w.t.Helper()
	leases, err := s.Claim(context.Background(), w.org, w.gwID, txapp.MaxClaim)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, l := range leases {
		if l.Correlate == "pc-"+txn.String() {
			return l, true
		}
	}
	return txapp.Lease{}, false
}

// TestINV09_NoAutomaticRetryAfterUnknownThroughReconciliation (M7 part):
// after an UNKNOWN outcome, reported by the gateway or swept, nothing
// automatic frees an identical irreversible refund. Whatever the agent
// resubmits (the same action, a new action id, from another run) and
// whatever reconciliation receives (verifier reads of every kind, before
// or after the verifier's window, late reports of every outcome, closed
// windows, more sweeps, an expired permit, a person asking for another
// read), the identical refund never gets a new permit. Its reservation and
// dedupe claim stay held until evidence shows that the refund happened,
// which commits them; nothing here ever releases them. Releasing ("did not
// occur") is an independent person's security-key action on the release
// page (HR-192), which no automatic path reaches.
func TestINV09_NoAutomaticRetryAfterUnknownThroughReconciliation(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	s := w.verifier()
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	person, _ := w.reconciler("rita")
	grant := w.grant("100000")
	run := w.run(grant.ID, ids.UUID{})
	n := 0

	rapid.Check(t, func(rt *rapid.T) {
		n++
		charge := fmt.Sprintf("ch_inv09x%d", n)
		amount := rapid.SampledFrom([]string{"1.00", "12.50", "30.00"}).Draw(rt, "amount")
		w.refundable(charge)
		act := ids.NewV7()
		first := w.authorize(w.request(run, act, charge, amount))
		if first.Permit == "" {
			rt.Fatalf("the first refund: %s (%s)", first.Decision, decisive(first))
		}
		if _, err := w.auth.BeginDispatch(ctx, w.gw, first.PermitID, first.Epoch, finalize.Outbound{}); err != nil {
			rt.Fatal(err)
		}
		txn := first.TransactionID
		swept := rapid.Bool().Draw(rt, "swept")
		if swept {
			w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '1 minute' WHERE id = $1", first.PermitID)
			if _, unknown, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil || unknown != 1 {
				rt.Fatalf("sweep: %d unknown, %v", unknown, err)
			}
		} else if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: first.PermitID, Outcome: finalize.Unknown, DispatchMS: -1}); err != nil {
			rt.Fatal(err)
		}
		var want map[string]string
		if err := json.Unmarshal([]byte(w.str("SELECT verify_expect::text FROM pc.permits WHERE id = $1", first.PermitID)), &want); err != nil {
			rt.Fatal(err)
		}

		occurred := false
		check := func(after string) {
			if r := w.authorize(w.request(run, ids.NewV7(), charge, amount)); r.Permit != "" || decisive(r) != pipeline.ReasonReconciliation {
				rt.Fatalf("after %s: an identical refund got %s, permit %q (%s)", after, r.Decision, r.Permit, decisive(r))
			}
			expect := "HELD OPEN HELD UNKNOWN"
			if occurred {
				expect = "SUCCEEDED OCCURRED COMMITTED UNKNOWN"
			}
			got := w.str(`SELECT coalesce((SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1), 'no-claim') || ' ' ||
				coalesce((SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'unknown_outcome'), 'no-task') || ' ' ||
				coalesce((SELECT string_agg(DISTINCT state, ',') FROM pc.reservations WHERE transaction_id = $1), 'no-reservation') || ' ' ||
				(SELECT state FROM pc.permits WHERE transaction_id = $1)`, txn)
			if got != expect {
				rt.Fatalf("after %s: claim, task, reservations and permit are %s, want %s", after, got, expect)
			}
		}
		check("the unknown outcome")

		for range rapid.IntRange(1, 6).Draw(rt, "steps") {
			var step string
			switch rapid.IntRange(0, 7).Draw(rt, "kind") {
			case 0:
				step = "the agent resubmitting the same action"
				if r := w.authorize(w.request(run, act, charge, amount)); !r.Repeat || r.Permit != "" {
					rt.Fatalf("%s: repeat %v, permit %q", step, r.Repeat, r.Permit)
				}
			case 1:
				step = "the agent resubmitting from another run"
				other := w.run(grant.ID, ids.UUID{})
				if r := w.authorize(w.request(other, ids.NewV7(), charge, amount)); r.Permit != "" || decisive(r) != pipeline.ReasonReconciliation {
					rt.Fatalf("%s: %s, permit %q (%s)", step, r.Decision, r.Permit, decisive(r))
				}
			case 2:
				o := rapid.SampledFrom(m7Observations).Draw(rt, "observation")
				late := rapid.Bool().Draw(rt, "after the window")
				step = "a verifier read: " + o.name
				if late {
					step += ", after the window"
					w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '11 minutes' WHERE id = $1", first.PermitID)
				}
				w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() - interval '1 hour' WHERE transaction_id = $1 AND state = 'PENDING'", txn)
				l, ok := w.m7TryLease(s, txn)
				if !ok {
					rt.Logf("%s: no verification to lease", step)
					continue
				}
				r := o.report(want)
				r.Task, r.Secret = l.Task, l.Secret
				a, err := s.Report(ctx, w.org, w.gwID, r)
				if err != nil {
					rt.Fatalf("%s: %v", step, err)
				}
				if a.Resolved != (o.occurred && !occurred) {
					rt.Fatalf("%s: resolved %v with occurred %v before", step, a.Resolved, occurred)
				}
				occurred = occurred || o.occurred
			case 3:
				outcome := rapid.SampledFrom([]finalize.Outcome{finalize.Accepted, finalize.Failed, finalize.Unknown}).Draw(rt, "late outcome")
				step = "a late " + string(outcome) + " report"
				_, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: first.PermitID, Outcome: outcome, TargetStatus: 200, DispatchMS: -1})
				switch {
				case !swept && !errors.Is(err, finalize.ErrNotDispatching):
					rt.Fatalf("%s after the gateway's own unknown: %v, want ErrNotDispatching", step, err)
				case swept && err != nil:
					rt.Fatalf("%s after the sweeper: %v", step, err)
				}
				occurred = occurred || (swept && outcome == finalize.Accepted)
			case 4:
				step = "the verifier's window closing"
				w.db.AdminExec(t, `UPDATE pc.verifications SET created_at = now() - interval '1 hour', deadline_at = now() - interval '1 second'
					WHERE transaction_id = $1 AND state = 'PENDING'`, txn)
				if _, err := s.Expire(ctx, w.org); err != nil {
					rt.Fatal(err)
				}
			case 5:
				step = "another sweep"
				if _, _, err := w.auth.Sweep(ctx, w.org, time.Nanosecond); err != nil {
					rt.Fatal(err)
				}
			case 6:
				step = "the permit expiring, then a sweep"
				w.db.AdminExec(t, "UPDATE pc.permits SET expires_at = now() - interval '1 second' WHERE id = $1", first.PermitID)
				if _, _, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil {
					rt.Fatal(err)
				}
			case 7:
				step = "a person asking for another read"
				if _, err := rec.RequestVerification(person, txn); err != nil {
					rt.Fatalf("%s: %v", step, err)
				}
			}
			check(step)
		}
		// Nothing of this refund stays due for the next one's leases.
		w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() + interval '1 day' WHERE transaction_id = $1 AND state = 'PENDING'", txn)
	})
}

// m7Verifiers verifies receipts of each type with the deployment's receipts
// key, as a relying party pinning it would.
func (w *world) m7Verifiers() map[string]*jws.Verifier {
	w.t.Helper()
	signer, ok := w.auth.Receipts.(*jws.Signer)
	if !ok {
		w.t.Fatalf("receipts signer %T", w.auth.Receipts)
	}
	out := map[string]*jws.Verifier{}
	for _, typ := range []string{finalize.TypeDecisionReceipt, finalize.TypeExecutionReceipt, txapp.TypeEffectReceipt} {
		v, err := jws.NewVerifier(typ, map[string]ed25519.PublicKey{signer.KeyID(): signer.Public()})
		if err != nil {
			w.t.Fatal(err)
		}
		out[typ] = v
	}
	return out
}

// m7Pap verifies a receipt and returns its pap claims.
func (w *world) m7Pap(v *jws.Verifier, receipt string) map[string]any {
	w.t.Helper()
	payload, _, err := v.Verify(receipt)
	if err != nil {
		w.t.Fatalf("a receipt does not verify: %v", err)
	}
	var c struct {
		Pap map[string]any `json:"pap"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		w.t.Fatal(err)
	}
	return c.Pap
}

// TestINV11_AValidSignatureNeverReadsAsAnEffect (M7 part): the decision
// and execution receipts of an accepted refund, of an accepted refund in
// monitor mode, of a delegated one on an SDK channel and of a late
// acceptance after the sweeper marked the dispatch UNKNOWN all verify with
// the deployment's receipts key, and none of them is an effect: the
// execution receipt claims no effect state, and each transaction has no
// effect state and no level reached, even where the late acceptance
// resolved the reconciliation and committed the budget. An effect appears
// only from a verifier's observation, at the state and level that
// observation reached, naming it. Across the database, every transaction's
// effect state is its latest effect receipt's, and every CONFIRMED receipt
// names observations that found the object, or a person.
func TestINV11_AValidSignatureNeverReadsAsAnEffect(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})

	accepted := w.recorded(run, "ch_1", "30.00", finalize.Accepted, "re_1")
	monitor := w.authorize(w.through(w.withConnection(pipeline.ModeMonitor), run, "ch_2", "20.00"))
	sdk := w.request(run, ids.NewV7(), "ch_3", "10.00")
	onSDK := sdk.Action.Action
	onSDK.Channel = "sdk"
	p, err := actionir.Encode(onSDK)
	if err != nil {
		t.Fatal(err)
	}
	sdk.Action = p
	delegated := w.authorize(sdk)
	for _, c := range []struct {
		r finalize.Result
		o finalize.Outcome
	}{{monitor, finalize.Accepted}, {delegated, finalize.Delegated}} {
		if c.r.Permit == "" {
			t.Fatalf("no permit: %s (%s)", c.r.Decision, decisive(c.r))
		}
		if _, err := w.auth.BeginDispatch(ctx, w.gw, c.r.PermitID, c.r.Epoch, finalize.Outbound{}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: c.r.PermitID, Outcome: c.o, TargetStatus: 200, DispatchMS: 7, TargetRef: "re_9"}); err != nil {
			t.Fatal(err)
		}
	}
	late := w.dispatched(run, "ch_4", "5.00")
	w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '1 minute' WHERE id = $1", late.PermitID)
	if _, unknown, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil || unknown != 1 {
		t.Fatalf("sweep: %d unknown, %v", unknown, err)
	}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: late.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: -1, TargetRef: "re_4"}); err != nil {
		t.Fatal(err)
	}
	if got := w.str("SELECT state || ' ' || resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1", late.TransactionID); got != "OCCURRED late_report" {
		t.Fatalf("the late acceptance: %s", got)
	}

	v := w.m7Verifiers()
	auditor := w.reader(tdomain.RoleAuditor, tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()})
	e := &txapp.Explorer{Pool: w.pool}
	for name, c := range map[string]struct {
		r       finalize.Result
		outcome string
	}{
		"accepted": {accepted, "accepted"}, "monitor": {monitor, "accepted"}, "delegated": {delegated, "delegated"}, "late acceptance": {late, "unknown"},
	} {
		if d := w.m7Pap(v[finalize.TypeDecisionReceipt], w.str("SELECT receipt_jws FROM pc.decision_receipts WHERE transaction_id = $1", c.r.TransactionID)); d["kind"] != "decision" {
			t.Fatalf("%s: decision receipt %v", name, d)
		}
		x := w.m7Pap(v[finalize.TypeExecutionReceipt], w.str("SELECT receipt_jws FROM pc.execution_receipts WHERE transaction_id = $1", c.r.TransactionID))
		if x["kind"] != "execution" || x["outcome"] != c.outcome {
			t.Fatalf("%s: execution receipt %v", name, x)
		}
		for _, claim := range []string{"state", "effect", "achieved", "level"} {
			if _, ok := x[claim]; ok {
				t.Fatalf("%s: the execution receipt claims %q: %v", name, claim, x)
			}
		}
		if got := w.str(`SELECT coalesce(effect_state, 'none') || ' ' || coalesce(effect_level_achieved, 'none') || ' ' ||
			(SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1)::text FROM pc.transactions WHERE id = $1`, c.r.TransactionID); got != "none none 0" {
			t.Fatalf("%s: effect state, level and receipts %q, want none", name, got)
		}
		ev, err := e.TransactionEvidence(auditor, c.r.TransactionID)
		if err != nil || ev.Transaction.Effect != "" || ev.Transaction.Achieved != "" || len(ev.Effects) != 0 {
			t.Fatalf("%s: the explorer shows effect %q at %q with %d receipts: %v", name, ev.Transaction.Effect, ev.Transaction.Achieved, len(ev.Effects), err)
		}
	}

	// Only what the verifier observes becomes the effect, at its level.
	read := func(status string) txapp.Applied {
		t.Helper()
		w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", accepted.TransactionID)
		l := w.lease(s, accepted.TransactionID)
		a, err := s.Report(ctx, w.org, w.gwID, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refundOf("ch_1", status, "30.00")})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if a := read("pending"); a.State != txdomain.PropagationPending {
		t.Fatalf("pending: %+v", a)
	}
	confirmed := read("succeeded")
	if confirmed.State != txdomain.Confirmed {
		t.Fatalf("settled: %+v", confirmed)
	}
	pap := w.m7Pap(v[txapp.TypeEffectReceipt], w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 AND state = 'CONFIRMED'", accepted.TransactionID))
	b, _ := pap["basis"].(map[string]any)
	if obs, _ := b["observations"].([]any); pap["achieved"] != "follow_up" || b["kind"] != "verifier" || len(obs) != 1 || obs[0] != confirmed.Observation.String() {
		t.Fatalf("the confirmed receipt %v, want the verifier's observation %s", pap, confirmed.Observation)
	}

	// Across the database: the effect state is the latest effect receipt's,
	// and a CONFIRMED receipt rests on observations that found the object,
	// or on a person.
	if n := w.count(`SELECT count(*) FROM pc.transactions t WHERE coalesce(t.effect_state, '') <>
		coalesce((SELECT state FROM pc.effect_receipts e WHERE e.org_id = t.org_id AND e.transaction_id = t.id ORDER BY seq DESC LIMIT 1), '')`); n != 0 {
		t.Fatalf("%d transactions whose effect state is not their latest effect receipt's", n)
	}
	type row struct {
		txn, state, jws string
	}
	var rows []row
	if err := w.pool.InTenantTx(ctx, w.org, func(ctx context.Context, tx db.TenantTx) error {
		rs, err := tx.Query(ctx, "SELECT transaction_id::text, state, receipt_jws FROM pc.effect_receipts ORDER BY transaction_id, seq")
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.txn, &r.state, &r.jws); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no effect receipts to check")
	}
	for _, r := range rows {
		pap := w.m7Pap(v[txapp.TypeEffectReceipt], r.jws)
		if pap["state"] != r.state || pap["txn"] != r.txn {
			t.Fatalf("an effect receipt claims %v for %s %s", pap, r.txn, r.state)
		}
		if r.state != string(txdomain.Confirmed) {
			continue
		}
		b, _ := pap["basis"].(map[string]any)
		obs, _ := b["observations"].([]any)
		switch b["kind"] {
		case "person":
			if b["person"] == nil {
				t.Fatalf("a person-based CONFIRMED receipt names nobody: %v", pap)
			}
		case "verifier", "target_log":
			if len(obs) == 0 {
				t.Fatalf("a CONFIRMED receipt names no observation: %v", pap)
			}
			for _, o := range obs {
				if n := w.count("SELECT count(*) FROM pc.observations WHERE id = $1::uuid AND transaction_id = $2::uuid AND found",
					fmt.Sprint(o), r.txn); n != 1 {
					t.Fatalf("a CONFIRMED receipt names observation %v, which found nothing for %s", o, r.txn)
				}
			}
		default:
			t.Fatalf("a CONFIRMED receipt rests on %v: %v", b["kind"], pap)
		}
	}
	if !slices.ContainsFunc(rows, func(r row) bool { return r.state == string(txdomain.Confirmed) }) {
		t.Fatal("no CONFIRMED receipt was checked")
	}
}
