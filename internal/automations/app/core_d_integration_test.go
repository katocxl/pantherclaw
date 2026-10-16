// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The core-C review fixes (D102).

// TestD102_EngageDuringRolloutConfirm (C1): the kill switch engaged while
// a ROLLOUT confirmation is applying never deadlocks; both finish and the
// automation stays PAUSED (KILL_SWITCH).
func TestD102_EngageDuringRolloutConfirm(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutCohort, 5)
	en, err := e.svc.RequestEnable(e.alice.cli, v.ID, autodomain.RolloutFull, nil, ids.UUID{})
	if err != nil {
		t.Fatal(err)
	}
	signers := []person{e.bob, e.cat}[:en.Required]
	for _, p := range signers[:len(signers)-1] {
		if _, err := e.svc.Changes.Confirm(p.page, en.Request.ID, e.sign(p, en.Request)); err != nil {
			t.Fatal(err)
		}
	}
	last := signers[len(signers)-1]
	ceremony := e.sign(last, en.Request)
	confirmed := make(chan error, 1)
	err = e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		// Engage's order: the containment row, then every ACTIVE automation.
		if _, err := tx.Exec(ctx, `UPDATE pc.org_containment SET kill_switch = true, epoch = epoch + 1, engaged_by = 'user:test',
			engaged_at = now(), engage_reason = 'test' WHERE org_id = $1`, e.org); err != nil {
			return err
		}
		go func() {
			_, err := e.svc.Changes.Confirm(last.page, en.Request.ID, ceremony)
			confirmed <- err
		}()
		// Let the confirmation reach its lock wait before pausing.
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
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
		_, err := e.svc.Pause(ctx, tx.Pgx(), e.org, autodomain.PauseSelector{All: true}, autodomain.PauseKillSwitch)
		return err
	})
	if err != nil {
		t.Fatalf("engage: %v", err)
	}
	if err := <-confirmed; err != nil {
		t.Fatalf("confirm: %v", err)
	}
	got, err := e.svc.GetAutomation(e.alice.cli, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Rollout != autodomain.RolloutFull || got.State != autodomain.StatePaused || got.PauseReason != autodomain.PauseKillSwitch {
		t.Errorf("after engage and confirm: %s %s %s", got.Rollout, got.State, got.PauseReason)
	}
}

// TestD102_VoidAndExpiryRevokeTheRowsGrants (L1).
func TestD102_VoidAndExpiryRevokeTheRowsGrants(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	b, bv := e.enabled("payouts", autodomain.RolloutCohort, 5)
	g, err := e.issue(b, bv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.VoidCeiling(context.Background(), e.org, b.Ceiling.ID, "TEST"); err != nil {
		t.Fatal(err)
	}
	if s := e.grantState(g); s != "REVOKED" {
		t.Errorf("a void ceiling's grant is %s", s)
	}

	c, cv := e.enabled("credits", autodomain.RolloutCohort, 5)
	h, err := e.issue(c, cv, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The row's dates are frozen for pc_app; move them as the owner.
	e.db.AdminExec(t, "ALTER TABLE pc.automation_ceilings DISABLE TRIGGER USER")
	e.db.AdminExec(t, `UPDATE pc.automation_ceilings SET created_at = now() - interval '2 days', review_by = now() - interval '1 minute'
		WHERE org_id = $1 AND id = $2`, e.org.UUID(), c.Ceiling.ID)
	e.db.AdminExec(t, "ALTER TABLE pc.automation_ceilings ENABLE TRIGGER USER")
	swept, err := e.svc.SweepOrg(context.Background(), e.org)
	if err != nil || swept.Expired != 1 {
		t.Fatalf("swept %+v: %v", swept, err)
	}
	if s := e.grantState(h); s != "REVOKED" {
		t.Errorf("an expired ceiling's grant is %s", s)
	}
	if got, _ := e.svc.GetAutomation(e.alice.cli, a.ID); got.State != autodomain.StateActive {
		t.Errorf("another automation was touched: %s", got.State)
	}
}

// TestD102_PrefixWithoutDefinitionsFailsClosed (L2): the env's operations
// cannot list definitions, so a prefix is refused.
func TestD102_PrefixWithoutDefinitionsFailsClosed(t *testing.T) {
	e := newEnv(t)
	a, err := e.svc.CreateAutomation(e.alice.cli, "refunds", "Refund small tickets.", autodomain.WorkAgent, e.alice.id)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(e.definition(5), "operations: [payments.refund.create]", "operations: [payments.*]", 1)
	dv, err := e.svc.CreateDraftVersion(e.alice.cli, a.ID, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := e.svc.ValidateVersion(e.alice.cli, dv.ID)
	if err != nil || ok {
		t.Fatalf("validated a prefix without definitions: %v %v", ok, err)
	}
	found := false
	for _, f := range got.Findings {
		found = found || (strings.HasSuffix(f.Path, "/bounds/operations/0") && strings.Contains(f.Message, "could not be checked"))
	}
	if !found {
		t.Errorf("findings %+v", got.Findings)
	}
}

// TestD102_SweepResolvesItsFailure (L6).
func TestD102_SweepResolvesItsFailure(t *testing.T) {
	e := newEnv(t)
	a, _ := e.enabled("refunds", autodomain.RolloutShadow, 5)
	e.exec(`INSERT INTO pc.operational_failures (org_id, id, kind, summary, next_step, deadline, dedupe_key)
		VALUES ($1, gen_random_uuid(), $2, 'failed', 'look', now() + interval '1 day', $3)`,
		e.org, autoapp.FailureSweep, "sweep:"+a.Ceiling.ID.String())
	if _, err := e.svc.SweepOrg(context.Background(), e.org); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM pc.operational_failures WHERE org_id = $1 AND kind = $2 AND state = 'RESOLVED'`,
		e.org, autoapp.FailureSweep); n != 1 {
		t.Errorf("resolved %d", n)
	}
}

// TestD102_RevokeOneGrantOfTheExecution: scope GRANT revokes the grant
// only when it belongs to the execution named.
func TestD102_RevokeOneGrantOfTheExecution(t *testing.T) {
	e := newEnv(t)
	a, v := e.enabled("refunds", autodomain.RolloutCohort, 5)
	g, err := e.issue(a, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	revoke := func(execution ids.UUID) ([]string, error) {
		var out []string
		err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			revoked, err := e.grants.RevokeForAutomationTx(ctx, tx, grantsapp.AutomationRevoke{
				Org: e.org, Automation: a.ID, Execution: execution, ServiceAccount: a.ServiceAccount,
				Grant: g.ID.UUID(), Scope: grantsapp.RevokeScopeGrant, Reason: "launch failed",
			})
			for _, id := range revoked {
				out = append(out, id.String())
			}
			return err
		})
		return out, err
	}
	if _, err := revoke(ids.NewV7()); !errors.Is(err, grantsapp.ErrGrantNotFound) {
		t.Errorf("another execution's grant: %v", err)
	}
	if got, err := revoke(g.Execution); err != nil || len(got) != 1 || e.grantState(g) != "REVOKED" {
		t.Errorf("revoked %v: %v (%s)", got, err, e.grantState(g))
	}
}

// TestD102_CreateDraftTxIsOneUnit (D103 T1): the automation, its identity
// and its version roll back with the caller's transaction, and a taken
// name leaves the transaction usable.
func TestD102_CreateDraftTxIsOneUnit(t *testing.T) {
	e := newEnv(t)
	draft := func(name string) autoapp.Draft {
		return autoapp.Draft{
			Name: name, Purpose: "Refund small tickets.", Kind: autodomain.WorkAgent, Owner: e.alice.id,
			Definition: []byte(e.definition(5)),
		}
	}
	errLater := errors.New("the tests could not be stored")
	err := e.pool.InTenantTx(e.alice.cli, e.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, _, err := e.svc.CreateDraftTx(ctx, tx, draft("refunds")); err != nil {
			return err
		}
		return errLater
	})
	if !errors.Is(err, errLater) {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM pc.service_accounts WHERE org_id = $1 AND name LIKE 'automation-%'`, e.org) +
		e.count(`SELECT count(*) FROM pc.automations WHERE org_id = $1`, e.org); n != 0 {
		t.Fatalf("a rolled-back draft left %d rows", n)
	}
	var v autoapp.Version
	err = e.pool.InTenantTx(e.alice.cli, e.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, _, err := e.svc.CreateDraftTx(ctx, tx, draft("refunds")); err != nil {
			return err
		}
		if _, _, err := e.svc.CreateDraftTx(ctx, tx, draft("refunds")); !errors.Is(err, autoapp.ErrNameTaken) {
			t.Errorf("a taken name: %v", err)
		}
		var err error
		_, v, err = e.svc.CreateDraftTx(ctx, tx, draft("payouts"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM pc.automations WHERE org_id = $1`, e.org); n != 2 || v.ID.IsZero() {
		t.Errorf("%d automations, version %s", n, v.ID)
	}
}
