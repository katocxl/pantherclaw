// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The core-D review fixes (D106).

func (e *env) confirmEnable(v ids.UUID, rollout autodomain.Rollout) {
	e.t.Helper()
	var cohort []ids.UUID
	if rollout == autodomain.RolloutCohort {
		cohort = []ids.UUID{e.agent}
	}
	en, err := e.svc.RequestEnable(e.alice.cli, v, rollout, cohort, ids.UUID{})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range []person{e.bob, e.cat}[:en.Required] {
		if _, err := e.svc.Changes.Confirm(p.page, en.Request.ID, e.sign(p, en.Request)); err != nil {
			e.t.Fatalf("confirm: %v", err)
		}
	}
}

func (e *env) openFailures(kind string) int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = $2 AND state <> 'RESOLVED'`, e.org, kind)
}

func (e *env) resolvedRecords() int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.incident.failure_resolved'`, e.org)
}

// TestD106_AuthorityRevokedRecordsCancellations (D1).
func TestD106_AuthorityRevokedRecordsCancellations(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	if _, _, err := e.svc.RevokeAuthority(e.alice.cli, a.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.automation.authority_revoked'
		AND convert_from(body, 'UTF8') LIKE '%"executions_canceled"%' AND convert_from(body, 'UTF8') LIKE '%"deliveries_not_verified"%'`,
		e.org); n != 1 {
		t.Errorf("authority_revoked records with the counts: %d", n)
	}
}

// TestD106_SweepResolvesThroughTheSink (D2): the resolution is recorded
// like a manual one, and a sweep with nothing open records none.
func TestD106_SweepResolvesThroughTheSink(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	e.exec(`INSERT INTO pc.operational_failures (org_id, id, kind, summary, next_step, deadline, dedupe_key)
		VALUES ($1, gen_random_uuid(), $2, 'failed', 'look', now() + interval '1 day', $3)`,
		e.org, autoapp.FailureSweep, "sweep:"+a.Ceiling.ID.String())
	for range 2 {
		if _, err := e.svc.SweepOrg(context.Background(), e.org); err != nil {
			t.Fatal(err)
		}
	}
	if open, rec := e.openFailures(autoapp.FailureSweep), e.resolvedRecords(); open != 0 || rec != 1 {
		t.Errorf("open %d, resolution records %d", open, rec)
	}
}

// TestD106_EnableResolvesAuthorityChanged (A3): enabling a new version
// resolves the automation's authority_changed failures; widening the
// rollout of the same version does not.
func TestD106_EnableResolvesAuthorityChanged(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutCohort, 5)
	if err := e.svc.VoidCeiling(context.Background(), e.org, a.Ceiling.ID, "TEST"); err != nil {
		t.Fatal(err)
	}
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 1 {
		t.Fatalf("authority_changed open %d", n)
	}
	e.confirmEnable(v.ID, autodomain.RolloutFull)
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 1 {
		t.Errorf("a ROLLOUT resolved authority_changed (%d open)", n)
	}
	next, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(e.definition(4)))
	if err != nil {
		t.Fatal(err)
	}
	if next, ok, err := e.svc.ValidateVersion(e.alice.cli, next.ID); err != nil || !ok {
		t.Fatalf("validate: %v %+v", err, next.Findings)
	}
	e.confirmEnable(next.ID, autodomain.RolloutShadow)
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 0 {
		t.Errorf("an ENABLE left %d authority_changed open", n)
	}
}

// TestD111_VoidCeilingTxInTheCallersTransaction: the void, its pause and
// its revocations commit or roll back with the caller's transaction.
func TestD111_VoidCeilingTxInTheCallersTransaction(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutCohort, 5)
	g, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	errMarking := errors.New("the marking failed")
	err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		if err := e.svc.VoidCeilingTx(ctx, tx, e.org, a.Ceiling.ID, "PUBLISHER_COMPROMISED"); err != nil {
			return err
		}
		return errMarking
	})
	if !errors.Is(err, errMarking) {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetAutomation(e.alice.cli, a.ID); got.State != autodomain.StateActive || e.grantState(g) != "ACTIVE" {
		t.Fatalf("a rolled-back void left %s, grant %s", got.State, e.grantState(g))
	}
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.svc.VoidCeilingTx(ctx, tx, e.org, a.Ceiling.ID, "PUBLISHER_COMPROMISED")
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := e.svc.GetAutomation(e.alice.cli, a.ID)
	if got.State != autodomain.StatePaused || got.PauseReason != autodomain.PauseCeilingVoid || e.grantState(g) != "REVOKED" {
		t.Errorf("after the void: %s %s, grant %s", got.State, got.PauseReason, e.grantState(g))
	}
	if n := e.count(`SELECT count(*) FROM pc.automation_ceilings WHERE org_id = $1 AND id = $2 AND state = 'VOID'
		AND void_reason = 'PUBLISHER_COMPROMISED'`, e.org, a.Ceiling.ID); n != 1 {
		t.Error("the ceiling is not VOID with the reason")
	}
	if err := e.pool.InTenantTx(context.Background(), ids.New[ids.Org](), func(ctx context.Context, tx db.TenantTx) error {
		return e.svc.VoidCeilingTx(ctx, tx, e.org, a.Ceiling.ID, "TEST")
	}); !errors.Is(err, db.ErrTenantMismatch) {
		t.Errorf("another org's transaction: %v", err)
	}
}

// TestD111_EnableResolvesByScope (G1): an ENABLE resolves the automation's
// authority_changed failures whatever their dedupe key (the engine's are
// keyed by execution), and leaves another automation's open.
func TestD111_EnableResolvesByScope(t *testing.T) {
	e := newEnv(t)
	a, _ := e.validated("refunds")
	other, _ := e.validated("payouts")
	scoped := func(automation ids.UUID, key string) {
		e.exec(`INSERT INTO pc.operational_failures (org_id, id, kind, summary, next_step, deadline, dedupe_key, scope)
			VALUES ($1, gen_random_uuid(), $2, 'failed', 'look', now() + interval '1 day', $3,
			jsonb_build_array(jsonb_build_object('type', 'automation', 'id', $4::text),
			                  jsonb_build_object('type', 'automation_execution', 'id', gen_random_uuid()::text)))`,
			e.org, autoapp.FailureAuthorityChanged, key, automation.String())
	}
	scoped(a.ID, "automation.authority_changed:"+ids.NewV7().String())
	scoped(a.ID, "automation.authority_changed:ceiling:"+ids.NewV7().String())
	scoped(other.ID, "automation.authority_changed:"+ids.NewV7().String())
	vs, err := e.svc.ListVersions(e.alice.cli, a.ID, 0, 10)
	if err != nil || len(vs) != 1 {
		t.Fatalf("versions %v %v", vs, err)
	}
	e.confirmEnable(vs[0].ID, autodomain.RolloutShadow)
	if n := e.openFailures(autoapp.FailureAuthorityChanged); n != 1 {
		t.Errorf("open after the ENABLE: %d, want only the other automation's", n)
	}
	if n := e.count(`SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND state <> 'RESOLVED'
		AND scope @> jsonb_build_array(jsonb_build_object('type', 'automation', 'id', $2::text))`, e.org, other.ID.String()); n != 1 {
		t.Error("another automation's failure was resolved")
	}
}

// TestD115_ResumePausedOnlyForItsReason (R2a): resume_launches resumes
// what is still paused for its reason, after revalidation, and nothing
// else.
func TestD115_ResumePausedOnlyForItsReason(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	inTx := func(fn func(ctx context.Context, tx db.TenantTx) error) {
		t.Helper()
		if err := e.pool.InTenantTx(context.Background(), e.org, fn); err != nil {
			t.Fatal(err)
		}
	}
	resume := func(reason autodomain.PauseReason) (bool, error) {
		var ok bool
		err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			ok, err = e.svc.ResumePaused(ctx, tx.Pgx(), e.org, a.ID, reason)
			return err
		})
		return ok, err
	}
	state := func() autodomain.State {
		got, err := e.svc.GetAutomation(e.alice.cli, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.State
	}
	if ok, err := resume(autodomain.PauseCoverageRecovery); ok || err != nil {
		t.Fatalf("resumed an ACTIVE automation: %v %v", ok, err)
	}
	inTx(func(ctx context.Context, tx db.TenantTx) error {
		_, err := e.svc.Pause(ctx, tx.Pgx(), e.org, autodomain.PauseSelector{Automations: []ids.UUID{a.ID}}, autodomain.PauseCoverageRecovery)
		return err
	})
	if ok, err := resume(autodomain.PauseUser); ok || err != nil || state() != autodomain.StatePaused {
		t.Fatalf("another reason resumed it: %v %v %s", ok, err, state())
	}
	e.exec(`UPDATE pc.org_containment SET kill_switch = true, engaged_by = 'user:test', engaged_at = now(), engage_reason = 'test'
		WHERE org_id = $1`, e.org)
	if ok, err := resume(autodomain.PauseCoverageRecovery); ok || err == nil || state() != autodomain.StatePaused {
		t.Fatalf("resumed during the kill switch: %v %v %s", ok, err, state())
	}
	e.exec(`UPDATE pc.org_containment SET kill_switch = false, engaged_by = NULL, engaged_at = NULL, engage_reason = NULL
		WHERE org_id = $1`, e.org)
	if ok, err := resume(autodomain.PauseCoverageRecovery); !ok || err != nil || state() != autodomain.StateActive {
		t.Fatalf("its own reason: %v %v %s", ok, err, state())
	}
	if ok, err := resume(autodomain.PauseCoverageRecovery); ok || err != nil {
		t.Errorf("resumed twice: %v %v", ok, err)
	}
}

// TestD118_EngageDuringResumeEndsPaused: the kill switch engaged while a
// resume holds its locks waits for it, then pauses the resumed automation
// (HR-283). Before D118 the engage skipped the still-PAUSED row and the
// resume committed ACTIVE under an engaged switch.
func TestD118_EngageDuringResumeEndsPaused(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	if _, _, err := e.svc.PauseAutomation(e.alice.cli, a.ID, false, "stop"); err != nil {
		t.Fatal(err)
	}
	engaged := make(chan error, 1)
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		if ok, err := e.svc.ResumePaused(ctx, tx.Pgx(), e.org, a.ID, autodomain.PauseUser); err != nil || !ok {
			t.Fatalf("resume: %v %v", ok, err)
		}
		bg := context.WithoutCancel(ctx) // the engage outlives this transaction
		go func() {
			engaged <- e.pool.InTenantTx(bg, e.org, func(ctx context.Context, other db.TenantTx) error {
				if _, err := other.Exec(ctx, `UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1,
					engaged_by = 'user:test', engaged_at = now(), engage_reason = 'test' WHERE org_id = $1`, e.org); err != nil {
					return err
				}
				_, err := e.svc.Pause(ctx, other.Pgx(), e.org, autodomain.PauseSelector{All: true}, autodomain.PauseKillSwitch)
				return err
			})
		}()
		// Commit once the engage waits on the resume's lock, or has
		// finished without waiting (the race this guards against).
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if len(engaged) > 0 {
				break
			}
			var waiting int
			if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, other db.TenantTx) error {
				return other.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
					WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
			}); err != nil {
				return err
			}
			if waiting > 0 {
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-engaged; err != nil {
		t.Fatalf("engage: %v", err)
	}
	got, err := e.svc.GetAutomation(e.alice.cli, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != autodomain.StatePaused || got.PauseReason != autodomain.PauseKillSwitch {
		t.Errorf("after the race: %s %s", got.State, got.PauseReason)
	}
}
