// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package support_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func TestHR389_BreakGlassNeedsDesignationAndOwnFreshKey(t *testing.T) {
	f := newFixture(t)
	ctx := f.as(person(f.custOrg, f.twin))
	if _, err := f.svc.ActivateBreakGlass(ctx, "Investigate outage", 60, fresh(f.twinKey)); !errors.Is(err, support.ErrNotHolder) {
		t.Fatalf("not holder: %v", err)
	}
	for _, role := range []td.RoleName{td.RoleOrgAdmin, td.RoleSupportReadOnly, "unknown"} {
		if _, err := f.svc.SetHolders(f.adminCtx(), []support.Designation{{User: f.twin, Role: role}}); !errors.Is(err, support.ErrDesignation) {
			t.Fatalf("role %s: %v", role, err)
		}
	}
	if _, err := f.svc.SetHolders(f.adminCtx(), []support.Designation{{User: f.twin, Role: td.RoleAuditor}}); err != nil {
		t.Fatal(err)
	}
	for _, su := range []*stepup.StepUp{nil, fresh(f.adminKey)} {
		if _, err := f.svc.ActivateBreakGlass(ctx, "Investigate outage", 60, su); !errors.Is(err, stepup.ErrStepUp) {
			t.Fatalf("foreign/missing key: %v", err)
		}
	}
	if _, err := f.svc.ActivateBreakGlass(ctx, "Investigate outage", 61, fresh(f.twinKey)); !errors.Is(err, support.ErrActivation) {
		t.Fatalf("duration: %v", err)
	}
	a, err := f.svc.ActivateBreakGlass(ctx, "Investigate outage", 60, fresh(f.twinKey))
	if err != nil {
		t.Fatal(err)
	}
	if a.ExpiresAt.Sub(a.StartedAt).Minutes() != 60 {
		t.Fatal("activation exceeded duration")
	}
	if _, err := f.svc.ActivateBreakGlass(ctx, "Again", 10, fresh(f.twinKey)); !errors.Is(err, support.ErrAlreadyActive) {
		t.Fatalf("duplicate: %v", err)
	}
	c := person(f.custOrg, f.twin)
	c.Bindings = nil
	c, err = f.svc.BreakGlassCall(context.Background(), c, "/test/Read")
	if err != nil || c.BreakGlassActivation != a.ID || !c.CanAnywhere(td.PermEvidenceRead) || c.CanAnywhere(td.PermRoleBind) {
		t.Fatalf("activation caller: %+v, %v", c, err)
	}
	var calls int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.breakglass.call' AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'activation' = $1", []any{a.ID.String()}, &calls)
	if calls != 1 {
		t.Fatalf("audited calls: %d", calls)
	}
	if _, err := f.svc.SetHolders(f.adminCtx(), nil); err != nil {
		t.Fatal(err)
	}
	c.Bindings = nil
	c, err = f.svc.BreakGlassCall(context.Background(), c, "/test/Read")
	if err != nil || !c.BreakGlassActivation.IsZero() || c.CanAnywhere(td.PermEvidenceRead) {
		t.Fatalf("removed holder retains role: %+v, %v", c, err)
	}
	f.plans.edition = billing.Team
	if _, err := f.svc.SetHolders(f.adminCtx(), []support.Designation{{User: f.twin, Role: td.RoleAuditor}}); !errors.Is(err, support.ErrBreakGlassEdition) {
		t.Fatalf("edition: %v", err)
	}
}

type breakGlassNotifier struct {
	messages []napp.Message
	fail     bool
}

func (n *breakGlassNotifier) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	if n.fail {
		return napp.Enqueued{}, errors.New("notification store unavailable")
	}
	n.messages = append(n.messages, m)
	return napp.Enqueued{}, nil
}

func TestHR389_NotificationAndExpiryAreAuditedAndFailClosed(t *testing.T) {
	f := newFixture(t)
	n := &breakGlassNotifier{fail: true}
	f.svc = support.New(f.pool, support.Config{}, f.plans, n, nil) // self-hosted support-off still permits break-glass
	if _, err := f.svc.SetHolders(f.adminCtx(), []support.Designation{{User: f.twin, Role: td.RoleAuditor}}); err != nil {
		t.Fatal(err)
	}
	ctx := f.as(person(f.custOrg, f.twin))
	if _, err := f.svc.ActivateBreakGlass(ctx, "Outage", 60, fresh(f.twinKey)); err == nil {
		t.Fatal("activation committed without notification")
	}
	var count int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.breakglass_activations WHERE org_id = $1", []any{f.custOrg}, &count)
	if count != 0 {
		t.Fatal("notification failure did not roll back activation")
	}
	n.fail = false
	a, err := f.svc.ActivateBreakGlass(ctx, "Outage", 60, fresh(f.twinKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.messages) != 1 || n.messages[0].Type != "breakglass.activated" || len(n.messages[0].Personal) != 1 || n.messages[0].Personal[0] != f.admin {
		t.Fatalf("notification recipients: %+v", n.messages)
	}
	f.d.AdminDo(t, func(conn *pgx.Conn) error {
		if _, err := conn.Exec(context.Background(), "SET session_replication_role = replica"); err != nil {
			return err
		}
		if _, err := conn.Exec(context.Background(), "UPDATE pc.breakglass_activations SET started_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1", a.ID); err != nil {
			return err
		}
		_, err := conn.Exec(context.Background(), "SET session_replication_role = origin")
		return err
	})
	c := person(f.custOrg, f.twin)
	c.Bindings = nil
	c, err = f.svc.BreakGlassCall(context.Background(), c, "/test/Read")
	if err != nil || !c.BreakGlassActivation.IsZero() || len(c.Bindings) != 0 {
		t.Fatalf("expired role: %+v %v", c, err)
	}
	for range 2 {
		if err := f.svc.ExpireBreakGlass(context.Background(), f.custOrg); err != nil {
			t.Fatal(err)
		}
	}
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.breakglass.ended'", []any{f.custOrg}, &count)
	if count != 1 {
		t.Fatalf("expiry audited %d times", count)
	}
	if _, err := f.svc.ActivateBreakGlass(ctx, "Recovered", 1, fresh(f.twinKey)); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
}

func TestHR389_HolderLimitsDisabledUsersAndIDOR(t *testing.T) {
	f := newFixture(t)
	for _, in := range [][]support.Designation{
		{{User: f.twin, Role: td.RoleAuditor}, {User: f.twin, Role: td.RoleAuditor}},
		{{User: f.twin, Role: td.RoleAuditor}, {User: f.admin, Role: td.RoleAuditor}, {User: ids.NewV7(), Role: td.RoleAuditor}, {User: ids.NewV7(), Role: td.RoleAuditor}},
		{{User: f.staffUser, Role: td.RoleAuditor}},
	} {
		if _, err := f.svc.SetHolders(f.adminCtx(), in); !errors.Is(err, support.ErrDesignation) {
			t.Fatalf("invalid holders: %v", err)
		}
	}
	if _, err := f.svc.SetHolders(f.adminCtx(), []support.Designation{{User: f.twin, Role: td.RoleAuditor}}); err != nil {
		t.Fatal(err)
	}
	ctx := f.as(person(f.custOrg, f.twin))
	if _, err := f.svc.ActivateBreakGlass(ctx, "Outage", 1, &stepup.StepUp{Credential: f.twinKey, At: time.Now().Add(-6 * time.Minute)}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("stale key: %v", err)
	}
	a, err := f.svc.ActivateBreakGlass(ctx, "Outage", 1, fresh(f.twinKey))
	if err != nil {
		t.Fatal(err)
	}
	other := person(f.custOrg, f.admin)
	other.Bindings = nil
	if _, err := f.svc.EndBreakGlass(f.as(other), a.ID); !errors.Is(err, support.ErrActivationNotFound) {
		t.Fatalf("foreign activation: %v", err)
	}
	if _, err := f.svc.EndBreakGlass(f.as(person(f.staffOrg, f.staffUser)), a.ID); !errors.Is(err, support.ErrActivationNotFound) {
		t.Fatalf("cross-org activation: %v", err)
	}
	f.d.AdminExec(t, "UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2", f.custOrg, f.twin)
	c := person(f.custOrg, f.twin)
	c.Bindings = nil
	c, err = f.svc.BreakGlassCall(context.Background(), c, "/test/Read")
	if err != nil || !c.BreakGlassActivation.IsZero() {
		t.Fatalf("disabled holder retained role: %v", err)
	}
	if _, err := f.svc.EndBreakGlass(f.adminCtx(), a.ID); err != nil {
		t.Fatal(err)
	}
	f.d.AdminExec(t, "UPDATE pc.users SET state = 'ACTIVE' WHERE org_id = $1 AND id = $2", f.custOrg, f.twin)
	apiKey := person(f.custOrg, f.twin)
	apiKey.Credential = tapp.CredAPIKey
	if _, err := f.svc.ActivateBreakGlass(f.as(apiKey), "Outage", 1, fresh(f.twinKey)); !errors.Is(err, support.ErrNotHolder) {
		t.Fatalf("API key activation: %v", err)
	}
}

func TestTenancy_breakglass_holders(t *testing.T) { testBreakGlassTenancy(t, "breakglass_holders") }
func TestTenancy_breakglass_activations(t *testing.T) {
	testBreakGlassTenancy(t, "breakglass_activations")
}

func testBreakGlassTenancy(t *testing.T, table string) {
	f := newFixture(t)
	if _, err := f.svc.SetHolders(f.adminCtx(), []support.Designation{{User: f.twin, Role: td.RoleAuditor}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ActivateBreakGlass(f.as(person(f.custOrg, f.twin)), "Outage", 1, fresh(f.twinKey)); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.InTenantTx(context.Background(), f.staffOrg, func(ctx context.Context, tx db.TenantTx) error {
		var n int
		// table comes only from the two literals above.
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM pc."+table).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Fatalf("foreign rows visible in %s: %d", table, n)
		}
		_, err := tx.Exec(ctx, "DELETE FROM pc.breakglass_holders WHERE org_id = $1", f.custOrg)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var n int
	f.d.AdminQueryRow(t, "SELECT count(*) FROM pc.breakglass_holders WHERE org_id = $1", []any{f.custOrg}, &n)
	if n != 1 {
		t.Fatal("foreign deletion succeeded")
	}
}
