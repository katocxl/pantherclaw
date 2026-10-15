// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgresponse_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

func epoch(t *testing.T, pool *db.Pool, org ids.OrgID) int64 {
	t.Helper()
	var e int64
	if err := pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		if err := dbq.New(tx).InsertContainment(ctx, org); err != nil {
			return err
		}
		c, err := dbq.New(tx).GetContainmentNow(ctx, org)
		e = c.Epoch
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestHR248_AddingAndLiftingAControlRaisesTheEpoch: adding a control raises
// the containment epoch in the same transaction (and a rolled-back add
// raises nothing); lifting needs a restoration plan, raises the epoch
// again, and a lifted control is never lifted twice. pc_app can neither
// delete a control nor change its scope or control, and the active-control
// read no longer returns a lifted one.
func TestHR248_AddingAndLiftingAControlRaisesTheEpoch(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	e0 := epoch(t, pool, org)

	agent := ids.NewV7()
	action := pgresponse.Action{
		ID: ids.NewV7(), Kind: rdomain.KindContain, ScopeType: rdomain.ScopeAgent, ScopeID: agent.String(),
		Control: rdomain.DenyAll, Reason: "suspicious writes", Actor: "user:" + ids.NewV7().String(), Source: rdomain.SourcePerson,
	}
	errRollback := errors.New("rollback")
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := pgresponse.AddControl(ctx, tx, org, action, nil); err != nil {
			return err
		}
		return errRollback
	})
	if !errors.Is(err, errRollback) || epoch(t, pool, org) != e0 {
		t.Fatalf("rolled-back add: %v, epoch %d (was %d)", err, epoch(t, pool, org), e0)
	}

	var added pgresponse.Added
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		added, err = pgresponse.AddControl(ctx, tx, org, action, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if added.Epoch != e0+1 || epoch(t, pool, org) != e0+1 {
		t.Fatalf("epoch after add: %d / %d, want %d", added.Epoch, epoch(t, pool, org), e0+1)
	}
	active := func() int {
		var n int
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			rows, err := dbq.New(tx).ActiveContainmentControls(ctx, org)
			n = len(rows)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if active() != 1 {
		t.Fatalf("%d active controls, want 1", active())
	}
	// The Authority reads the control by the action's keys.
	cont, err := (&pgauthority.Reader{Pool: pool}).Containment(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := (&pgauthority.Reader{Pool: pool}).Controls(ctx, org, pipeline.ControlKeys{Agent: agent.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cont.Epoch != e0+1 || cs[0].ID != added.ControlID || cs[0].ScopeID != agent.String() || cs[0].Control != rdomain.DenyAll {
		t.Fatalf("authority containment: %+v %+v", cont, cs)
	}

	// pc_app cannot delete a control or change what it controls.
	for _, sql := range []string{
		"DELETE FROM pc.containment_controls WHERE id = $1",
		"UPDATE pc.containment_controls SET scope_id = 'x' WHERE id = $1",
		"UPDATE pc.containment_controls SET control = 'HOLD_WRITES' WHERE id = $1",
		"UPDATE pc.containment_controls SET expires_at = now() WHERE id = $1",
	} {
		err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, added.ControlID)
			return err
		})
		if err == nil {
			t.Errorf("pc_app ran %q", sql)
		}
	}
	// A lift that names no restoration plan is refused by the schema.
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.containment_controls SET lifted_at = now(), lifted_by = 'user:x' WHERE id = $1", added.ControlID)
		return err
	}); err == nil {
		t.Fatal("a control was lifted without a restoration plan")
	}

	plan := ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.restoration_plans (org_id, id, reason, requested_by) VALUES ($1, $2, 'fixed', 'user:x')", org, plan)
	lift := func() error {
		return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return pgresponse.LiftControl(ctx, tx, org, added.ControlID, plan, "user:reviewer")
		})
	}
	if err := lift(); err != nil {
		t.Fatal(err)
	}
	if e := epoch(t, pool, org); e != e0+2 {
		t.Fatalf("epoch after lift: %d, want %d", e, e0+2)
	}
	if active() != 0 {
		t.Fatalf("%d active controls after the lift", active())
	}
	if err := lift(); !errors.Is(err, pgresponse.ErrConflict) {
		t.Fatalf("second lift: %v", err)
	}
	if e := epoch(t, pool, org); e != e0+2 {
		t.Fatalf("epoch after a refused lift: %d", e)
	}
}

// TestIntResponseTablesAreTenantScoped: another org sees none of the rows.
func TestIntResponseTablesAreTenantScoped(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	ctx := context.Background()
	a, b := ids.New[ids.Org](), ids.New[ids.Org]()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'a'), ($2, 'b')", a, b)
	if err := pool.InTenantTx(ctx, a, func(ctx context.Context, tx db.TenantTx) error {
		_, err := pgresponse.AddControl(ctx, tx, a, pgresponse.Action{
			ID: ids.NewV7(), Kind: rdomain.KindContain, ScopeType: rdomain.ScopeRun, ScopeID: ids.NewV7().String(),
			Control: rdomain.DenyAll, Reason: "r", Actor: "user:x", Source: rdomain.SourcePerson,
		}, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"containment_controls", "response_actions"} {
		var n int
		if err := pool.InTenantTx(ctx, b, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM pc."+table).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("org b sees %d rows of %s", n, table)
		}
	}
}
