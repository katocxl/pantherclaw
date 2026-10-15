// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/posture/app"
	"github.com/katocxl/pantherclaw/internal/posture/domain"
)

var alice = evdomain.Actor{Type: "user", ID: "alice"}

func reconcile(t *testing.T, o *exposuretest.Org) (exapp.Recomputed, app.Summary) {
	t.Helper()
	var rec exapp.Recomputed
	var sum app.Summary
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		if rec, err = exapp.Recompute(ctx, tx, "manual", 0); err != nil {
			return err
		}
		sum, err = app.Reconcile(ctx, tx, rec)
		return err
	})
	return rec, sum
}

func findings(t *testing.T, o *exposuretest.Org) map[domain.Kind]dbq.PcPostureFinding {
	t.Helper()
	out := map[domain.Kind]dbq.PcPostureFinding{}
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPostureFindings(ctx, dbq.ListPostureFindingsParams{
			OrgID: o.Org, States: []string{}, MaxRows: 200, AllAgents: true, AgentIds: []ids.UUID{}, OrgScope: true,
		})
		for _, r := range rows {
			out[domain.Kind(r.Kind)] = r
		}
		return err
	})
	return out
}

func count(t *testing.T, o *exposuretest.Org, sql string, args ...any) int {
	t.Helper()
	var n int
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
	return n
}

// TestIntReconcileOpensAndRecordsFindings: the first recomputation opens a
// finding per kind it shows, each with its affected paths, an OPENED event
// and a posture.finding ledger entry; the next one only sees them again.
func TestIntReconcileOpensAndRecordsFindings(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 1, "40 days", "payments.*")
	o.Credential(t, "100 days")
	_, sum := reconcile(t, o)
	got := findings(t, o)
	for _, k := range []domain.Kind{
		domain.UnownedAgent, domain.UncoveredPath, domain.StaleCredential, domain.UnusedAuthority,
		domain.UnsafeDelegation,
	} {
		f, ok := got[k]
		if !ok || f.State != string(domain.Open) || len(f.AffectedPaths) == 0 {
			t.Errorf("%s: %+v %v", k, f, ok)
		}
	}
	if sum[domain.ActOpen] != len(got) {
		t.Fatalf("summary %v, %d findings", sum, len(got))
	}
	if n := count(t, o, `SELECT count(*) FROM pc.posture_finding_events WHERE kind = 'OPENED'`); n != len(got) {
		t.Fatalf("opened events: %d", n)
	}
	if n := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'posture.finding'`); n != len(got) {
		t.Fatalf("ledger entries: %d", n)
	}
	if _, sum = reconcile(t, o); sum[domain.ActOpen] != 0 || sum[domain.ActSeen] != len(got) {
		t.Fatalf("second pass: %v", sum)
	}
	if n := count(t, o, `SELECT count(*) FROM pc.posture_findings`); n != len(got) {
		t.Fatalf("duplicated: %d", n)
	}
}

// TestHR255_RemediatedOnlyByRecomputation: revoking the grant and
// recomputing remediates the grant's findings with the snapshot as proof,
// while the stale credential stays open; the database refuses a
// remediation on a snapshot older than the finding's last sighting, an
// acceptance past 90 days, and any change to a finding's history; a
// finding found again reopens.
func TestHR255_RemediatedOnlyByRecomputation(t *testing.T) {
	o := exposuretest.New(t)
	grant := o.Grant(t, o.Agent, 1, "40 days", "payments.*")
	o.Credential(t, "100 days")
	first, _ := reconcile(t, o)
	before := findings(t, o)

	// A person cannot remediate with an old snapshot: the trigger checks
	// the proof against the last sighting.
	reconcile(t, o) // a later sighting
	err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.posture_findings SET state = 'REMEDIATED', remediated_snapshot_id = $2 WHERE id = $1`,
			before[domain.UncoveredPath].ID, first.Snapshot.ID)
		return err
	})
	if err == nil {
		t.Fatal("remediated on a snapshot older than the last sighting")
	}

	o.Revoke(t, grant)
	rec, sum := reconcile(t, o)
	after := findings(t, o)
	for _, k := range []domain.Kind{domain.UncoveredPath, domain.UnusedAuthority, domain.UnsafeDelegation, domain.UnownedAgent} {
		f := after[k]
		if f.State != string(domain.Remediated) || f.RemediatedSnapshotID == nil || *f.RemediatedSnapshotID != rec.Snapshot.ID {
			t.Errorf("%s after revocation: %s %v", k, f.State, f.RemediatedSnapshotID)
		}
	}
	if after[domain.StaleCredential].State != string(domain.Open) || sum[domain.ActRemediate] != 4 {
		t.Fatalf("stale credential %s, summary %v", after[domain.StaleCredential].State, sum)
	}

	// Acceptance is bounded by the database too.
	stale := after[domain.StaleCredential].ID
	err = o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.posture_findings SET state = 'ACCEPTED_TEMPORARILY',
			accepted_until = now() + interval '91 days', accepted_reason = 'accepted for the pilot' WHERE id = $1`, stale)
		return err
	})
	if err == nil {
		t.Fatal("accepted for more than 90 days")
	}
	for _, sql := range []string{
		`UPDATE pc.posture_finding_events SET note = 'x'`, `DELETE FROM pc.posture_finding_events`,
		`DELETE FROM pc.posture_findings`, `UPDATE pc.posture_findings SET kind = 'unowned_agent'`,
	} {
		err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
		if err == nil {
			t.Errorf("allowed: %s", sql)
		}
	}

	// Granted again: the remediated findings reopen.
	o.Grant(t, o.Agent, 1, "40 days", "payments.*")
	if _, sum = reconcile(t, o); sum[domain.ActReopen] == 0 {
		t.Fatalf("not reopened: %v", sum)
	}
	if f := findings(t, o)[domain.UncoveredPath]; f.State != string(domain.Open) || f.RemediatedSnapshotID != nil {
		t.Fatalf("reopened: %s", f.State)
	}
}

// TestIntPostureLifecycle: a finding is assigned, tested, accepted for a
// while and reopened, each move recorded; remediation is not a manual
// move; an acceptance needs a reason and a bounded expiry; an expired
// acceptance reopens on the next recomputation.
func TestIntPostureLifecycle(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	reconcile(t, o)
	id := findings(t, o)[domain.UncoveredPath].ID
	step := func(fn func(ctx context.Context, tx db.TenantTx) error) error {
		return o.P.InTenantTx(context.Background(), o.Org, fn)
	}
	if err := step(func(ctx context.Context, tx db.TenantTx) error { return app.StartTesting(ctx, tx, id, alice, "") }); !errors.Is(err, app.ErrTransition) {
		t.Fatalf("testing before assignment: %v", err)
	}
	for _, fn := range []func(ctx context.Context, tx db.TenantTx) error{
		func(ctx context.Context, tx db.TenantTx) error { return app.Assign(ctx, tx, id, o.User, alice) },
		func(ctx context.Context, tx db.TenantTx) error {
			return app.StartTesting(ctx, tx, id, alice, "fix deployed")
		},
		func(ctx context.Context, tx db.TenantTx) error {
			return app.Note(ctx, tx, id, "waiting for the rollout", alice)
		},
	} {
		if err := step(fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, until := range []time.Duration{91 * 24 * time.Hour, -time.Hour} {
		err := step(func(ctx context.Context, tx db.TenantTx) error {
			return app.Accept(ctx, tx, id, time.Now().Add(until), "risk accepted for the pilot", alice)
		})
		if !errors.Is(err, app.ErrAcceptance) {
			t.Fatalf("acceptance %s: %v", until, err)
		}
	}
	if err := step(func(ctx context.Context, tx db.TenantTx) error {
		return app.Accept(ctx, tx, id, time.Now().Add(30*24*time.Hour), "risk accepted for the pilot", alice)
	}); err != nil {
		t.Fatal(err)
	}
	if f := findings(t, o)[domain.UncoveredPath]; f.State != string(domain.AcceptedTemporarily) || f.OwnerUserID == nil {
		t.Fatalf("accepted: %+v", f)
	}
	// Still found while accepted: it stays accepted.
	if _, sum := reconcile(t, o); sum[domain.ActExpire] != 0 {
		t.Fatalf("expired early: %v", sum)
	}
	// The acceptance ends: the next recomputation reopens it.
	o.D.AdminExec(t, `ALTER TABLE pc.posture_findings DISABLE TRIGGER posture_findings_transition`)
	o.D.AdminExec(t, `UPDATE pc.posture_findings SET accepted_until = now() - interval '1 minute', state_changed_at = now() - interval '1 day'
		WHERE id = $1`, id)
	o.D.AdminExec(t, `ALTER TABLE pc.posture_findings ENABLE TRIGGER posture_findings_transition`)
	if _, sum := reconcile(t, o); sum[domain.ActExpire] != 1 {
		t.Fatalf("expiry: %v", sum)
	}
	var events []string
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPostureFindingEvents(ctx, o.Org, id)
		for _, r := range rows {
			events = append(events, r.Kind)
		}
		return err
	})
	if !slices.Equal(events, []string{"OPENED", "ASSIGNED", "TESTING", "NOTE", "ACCEPTED", "EXPIRED"}) {
		t.Fatalf("history: %v", events)
	}
	if err := step(func(ctx context.Context, tx db.TenantTx) error { return app.Reopen(ctx, tx, id, "again", alice) }); !errors.Is(err, app.ErrTransition) {
		t.Fatalf("reopen an open finding: %v", err)
	}
}

// TestTenancy_posture_findings: another org reads none of an org's
// findings or their events, and cannot move one.
func TestTenancy_posture_findings(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	reconcile(t, o)
	id := findings(t, o)[domain.UncoveredPath].ID
	them := exposuretest.NewIn(t, o.D, o.P)
	for _, table := range []string{"posture_findings", "posture_finding_events"} {
		if n := count(t, them, "SELECT count(*) FROM pc."+table); n != 0 {
			t.Errorf("%s: another org reads %d rows", table, n)
		}
	}
	err := them.P.InTenantTx(context.Background(), them.Org, func(ctx context.Context, tx db.TenantTx) error {
		return app.Assign(ctx, tx, id, them.User, alice)
	})
	if !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("assigned another org's finding: %v", err)
	}
	err = them.P.InTenantTx(context.Background(), them.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.posture_finding_events (org_id, id, finding_id, kind, to_state, actor)
			VALUES ($1, $2, $3, 'NOTE', 'OPEN', 'x')`, o.Org, ids.NewV7(), id)
		return err
	})
	if err == nil {
		t.Fatal("an event written into another org")
	}
}

// TestHR255_CauseTypeFindingsRemediateWhenTheCauseIsFixed (D63 M1): naming
// an owner remediates unowned_agent on the next recomputation although
// the agent keeps its reach; a reach-type finding of the same agent stays
// open while its paths are reachable.
func TestHR255_CauseTypeFindingsRemediateWhenTheCauseIsFixed(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	reconcile(t, o)
	if f := findings(t, o); f[domain.UnownedAgent].State != string(domain.Open) || f[domain.UncoveredPath].State != string(domain.Open) {
		t.Fatalf("before: %v %v", f[domain.UnownedAgent].State, f[domain.UncoveredPath].State)
	}
	o.Claim(t, o.Agent)
	reconcile(t, o)
	f := findings(t, o)
	if f[domain.UnownedAgent].State != string(domain.Remediated) {
		t.Fatalf("owned agent's finding: %s", f[domain.UnownedAgent].State)
	}
	if f[domain.UncoveredPath].State != string(domain.Open) {
		t.Fatalf("reach-type finding remediated while reachable: %s", f[domain.UncoveredPath].State)
	}
}

// TestHR255_DatabaseHoldsTheLifecycle (L1, L2): a finding is inserted only
// OPEN; its proof, acceptance and state time change only with its state;
// and the proof is a snapshot later than its last sighting, never that
// sighting itself.
func TestHR255_DatabaseHoldsTheLifecycle(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	rec, _ := reconcile(t, o)
	f := findings(t, o)[domain.UncoveredPath]
	for _, sql := range []string{
		`UPDATE pc.posture_findings SET state = 'REMEDIATED', remediated_snapshot_id = last_snapshot_id WHERE id = $1`,
		`UPDATE pc.posture_findings SET remediated_at = now() WHERE id = $1`,
		`UPDATE pc.posture_findings SET accepted_reason = 'accepted for the pilot' WHERE id = $1`,
		`UPDATE pc.posture_findings SET state_changed_at = now() - interval '89 days' WHERE id = $1`,
	} {
		err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, f.ID)
			return err
		})
		if err == nil {
			t.Errorf("allowed: %s", sql)
		}
	}
	err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.posture_findings (org_id, id, kind, root_cause, title, affected_paths, severity,
			fingerprint, last_snapshot_id, state, remediated_snapshot_id, remediated_at)
			VALUES ($1, $2, 'unowned_agent', $3, 't', '{p}', 'low', $4, $5, 'REMEDIATED', $5, now())`,
			o.Org, ids.NewV7(), "agent:"+o.Agent.String(), make([]byte, 32), rec.Snapshot.ID)
		return err
	})
	if err == nil {
		t.Fatal("a finding inserted already remediated")
	}
}

// TestIntPostureActionsAreAudited (D63 M6): every person's move writes an
// audit.posture.finding_<event> entry with the finding, the states and
// the reason; a recomputation's own changes do not.
func TestIntPostureActionsAreAudited(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	reconcile(t, o)
	if n := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE 'audit.posture.%'`); n != 0 {
		t.Fatalf("recomputation audited: %d", n)
	}
	id := findings(t, o)[domain.UncoveredPath].ID
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		if err := app.Assign(ctx, tx, id, o.User, alice); err != nil {
			return err
		}
		return app.Accept(ctx, tx, id, time.Now().Add(24*time.Hour), "accepted for the pilot", alice)
	})
	for _, kind := range []string{"audit.posture.finding_assigned", "audit.posture.finding_accepted"} {
		if n := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind = '`+kind+`'
			AND convert_from(body, 'UTF8') LIKE '%`+id.String()+`%'`); n != 1 {
			t.Errorf("%s: %d", kind, n)
		}
	}
	if n := count(t, o, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.posture.finding_accepted'
		AND convert_from(body, 'UTF8') LIKE '%accepted for the pilot%' AND convert_from(body, 'UTF8') LIKE '%until%'`); n != 1 {
		t.Fatalf("acceptance audit lacks its reason or expiry: %d", n)
	}
}
