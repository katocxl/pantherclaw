// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	tdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// notes records the notifications a store enqueues, rendered from their
// templates.
type notes struct{ got []ndomain.Rendered }

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	r, err := ndomain.Render(m.Type, m.Params)
	if err != nil {
		return napp.Enqueued{}, err
	}
	n.got = append(n.got, r)
	return napp.Enqueued{Notification: ids.NewV7()}, nil
}

// TestHR112_TargetLogsFindEffectsWithoutReceipts: the target log of the
// connection lists what the target created. An object naming an unknown
// refund resolves it as occurred; one naming a refund the target refused
// makes its effect CONFLICTING; an object no receipt accounts for is an
// effect without a receipt, reported once with a security audit event and
// told to admins once per run.
func TestHR112_TargetLogsFindEffectsWithoutReceipts(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	told := &notes{}
	s := &tapp.Service{Store: &pgtransactions.Store{Pool: w.pool, Notify: told}, Receipts: w.auth.Receipts}
	run := w.run(w.grant("500").ID, ids.UUID{})
	unknown := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	failed := w.dispatched(run, "ch_2", "20.00")
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: failed.PermitID, Outcome: finalize.Failed, TargetStatus: 402, DispatchMS: 1}); err != nil {
		t.Fatal(err)
	}
	// Only the target log is due: the unknown refund's lookup waits.
	w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() + interval '1 hour'")

	if n, err := s.ScheduleTargetLogs(ctx, w.org); err != nil || n != 1 {
		t.Fatalf("scheduled %d: %v", n, err)
	}
	if n, _ := s.ScheduleTargetLogs(ctx, w.org); n != 0 {
		t.Fatal("a second target-log task while one is open")
	}
	leases, err := s.Claim(ctx, w.org, w.gwID, 16)
	if err != nil || len(leases) != 1 || leases[0].Purpose != tdomain.PurposeTargetLog || leases[0].Operation != "payments.refund.recent" {
		t.Fatalf("leases %+v %v", leases, err)
	}
	l := leases[0]
	now := time.Now().UTC().Truncate(time.Second)
	report := tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Complete: true, Items: []tapp.TargetLogItem{
		{ObjectRef: "re_unknown", Correlation: "pc-" + unknown.TransactionID.String(), Created: now},
		{ObjectRef: "re_refused", Correlation: "pc-" + failed.TransactionID.String(), Created: now},
		{ObjectRef: "re_console", Created: now},
		{ObjectRef: "re_foreign", Correlation: "pc-" + ids.NewV7().String(), Created: now},
	}}
	if _, err := s.Report(ctx, w.org, w.gwID, report); err != nil {
		t.Fatal(err)
	}

	if got := w.str("SELECT state || ' ' || resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'unknown_outcome'", unknown.TransactionID); got != "OCCURRED target_log" {
		t.Fatalf("the unknown refund: %s", got)
	}
	if got := w.str("SELECT state || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", failed.TransactionID); got != "CONFLICTING target_log" {
		t.Fatalf("the refused refund: %s", got)
	}
	if n := w.count("SELECT count(*) FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'conflicting_effect'", failed.TransactionID); n != 1 {
		t.Fatal("no conflicting-effect task for the refused refund")
	}
	if got := w.str("SELECT string_agg(object_ref, ',' ORDER BY object_ref) FROM pc.unreceipted_effects WHERE state = 'OPEN'"); got != "re_console,re_foreign" {
		t.Fatalf("unreceipted effects %s", got)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.effect_without_receipt'"); n != 2 {
		t.Fatalf("%d security events", n)
	}
	if len(told.got) != 1 || told.got[0].Type != "security.effect_without_receipt" || !strings.Contains(told.got[0].Body, " 2 new effects") {
		t.Fatalf("notifications %+v, want one for the run naming both", told.got)
	}
	if got := w.str("SELECT items_seen || '/' || matched || '/' || unmatched || '/' || complete FROM pc.target_log_runs"); got != "4/2/2/true" {
		t.Fatalf("run %s", got)
	}
	if res, sp := w.budget(); res != "0" || sp != "30" {
		t.Fatalf("budget reserved %s spent %s: the unknown refund commits, the refused one stays released", res, sp)
	}

	// The next window starts where the last complete one ended, less the
	// overlap, and an object seen again is not reported twice.
	if n, err := s.ScheduleTargetLogs(ctx, w.org); err != nil || n != 1 {
		t.Fatalf("next window: %d %v", n, err)
	}
	if n := w.count(`SELECT count(*) FROM pc.verifications v, pc.target_log_runs r WHERE v.purpose = 'target_log' AND v.state = 'PENDING'
		AND v.window_start = r.window_end - interval '5 minutes'`); n != 1 {
		t.Fatal("the next window does not overlap the last one by 5 minutes")
	}
	leases, err = s.Claim(ctx, w.org, w.gwID, 16)
	if err != nil || len(leases) != 1 || leases[0].Correlate != "" {
		t.Fatalf("next leases %+v %v", leases, err)
	}
	if _, err := s.Report(ctx, w.org, w.gwID, tapp.Report{
		Task: leases[0].Task, Secret: leases[0].Secret, HTTPStatus: 200, Complete: true,
		Items: []tapp.TargetLogItem{{ObjectRef: "re_console", Created: now}},
	}); err != nil {
		t.Fatal(err)
	}
	if n := w.count("SELECT count(*) FROM pc.unreceipted_effects"); n != 2 {
		t.Fatalf("%d unreceipted effects after seeing one again", n)
	}
	if len(told.got) != 1 {
		t.Fatalf("%d notifications after seeing one again", len(told.got))
	}
}
