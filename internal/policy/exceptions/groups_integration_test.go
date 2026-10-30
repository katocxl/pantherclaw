// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exceptions_test

import (
	"context"
	"errors"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e), Status: billing.StatusValid}, nil
}

// groupFixture is the exception fixture with a fleet cohort holding the
// fixture's agent and a second one, on Enterprise.
type groupFixture struct {
	*fixture
	cohort, second ids.UUID
}

func newGroupFixture(t *testing.T) *groupFixture {
	t.Helper()
	g := &groupFixture{fixture: newFixture(t), cohort: ids.NewV7(), second: ids.NewV7()}
	g.svc.Editions = edition(billing.Enterprise)
	g.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'refunder-2', 'DISCOVERED', 'test')", g.org, g.second)
	g.exec(t, "INSERT INTO pc.fleet_cohorts (org_id, id, name, owner_user_id, created_by) VALUES ($1, $2, 'refunders', $3, 'test')",
		g.org, g.cohort, g.alice)
	g.join(t, g.agent)
	g.join(t, g.second)
	return g
}

func (g *groupFixture) join(t *testing.T, agent ids.UUID) {
	t.Helper()
	g.exec(t, "INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by) VALUES ($1, $2, $3, 'test')", g.org, g.cohort, agent)
}

func (g *groupFixture) groupRequest() exceptions.GroupRequest {
	return exceptions.GroupRequest{
		Rule: "hold-large", Cohort: g.cohort, Operations: []string{op}, Reason: "Quarter-end backlog of reviewed refunds.",
		ExpiresIn: 7 * 24 * time.Hour,
	}
}

// approve runs the EXCEPTION change request's apply callback for subject,
// as the confirming transaction does.
func (g *groupFixture) approve(t *testing.T, subject ids.UUID) error {
	t.Helper()
	ctx := g.as(g.bob, tenancy.CredBrowserSession, td.RolePolicyPublisher)
	return g.p.InTenantTx(ctx, g.org, func(ctx context.Context, tx db.TenantTx) error {
		return g.svc.Apply(ctx, tx, papp.ChangeRequest{ID: ids.NewV7(), Kind: papp.ChangeException, Subject: subject})
	})
}

func (g *groupFixture) activeFor(t *testing.T, agent ids.UUID) []pdomain.Exception {
	t.Helper()
	var out []pdomain.Exception
	if err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = exceptions.ActiveFor(ctx, tx, g.org, agent)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR477_AnAgentJoiningLaterIsNotCovered: an exception group approved
// for a cohort waives the rule for exactly the agents the cohort held at
// approval, one exception row each; an agent added to the cohort
// afterwards is still decided by the rule, and revoking the group ends
// every member's exception.
// Covers: F602
func TestHR477_AnAgentJoiningLaterIsNotCovered(t *testing.T) {
	g := newGroupFixture(t)
	author := g.as(g.alice, tenancy.CredAccessToken, td.RolePolicyAuthor)
	group, cr, err := g.svc.RequestGroup(author, g.groupRequest())
	if err != nil {
		t.Fatal(err)
	}
	if group.State != exceptions.StatePending || cr.ID.IsZero() {
		t.Fatalf("requested %s with change request %s", group.State, cr.ID)
	}
	if len(g.activeFor(t, g.agent)) != 0 {
		t.Fatal("a pending group waived the rule")
	}
	// An agent that joins before approval is in the snapshot.
	early := ids.NewV7()
	g.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'early', 'DISCOVERED', 'test')", g.org, early)
	g.join(t, early)
	if err := g.approve(t, group.ID); err != nil {
		t.Fatal(err)
	}
	got, err := g.svc.GetGroup(author, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != exceptions.StateActive || got.Members == nil || *got.Members != 3 || len(got.Agents) != 3 {
		t.Fatalf("approved group %s with %v members, agents %v", got.State, got.Members, got.Agents)
	}
	for _, a := range []ids.UUID{g.agent, g.second, early} {
		if x := g.activeFor(t, a); len(x) != 1 || x[0].Rule != "hold-large" {
			t.Errorf("agent %s at approval: %v", a, x)
		}
	}
	late := ids.NewV7()
	g.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'late', 'DISCOVERED', 'test')", g.org, late)
	g.join(t, late)
	if x := g.activeFor(t, late); len(x) != 0 {
		t.Fatalf("an agent that joined after approval is covered: %v", x)
	}
	if n := g.count(t, "SELECT count(*) FROM pc.policy_exceptions WHERE group_id = $1", group.ID); n != 3 {
		t.Errorf("%d member rows, want the 3 snapshotted", n)
	}
	publisher := g.as(g.bob, tenancy.CredAccessToken, td.RolePolicyPublisher)
	if _, err := g.svc.RevokeGroup(publisher, group.ID, "backlog cleared"); err != nil {
		t.Fatal(err)
	}
	for _, a := range []ids.UUID{g.agent, g.second, early} {
		if x := g.activeFor(t, a); len(x) != 0 {
			t.Errorf("agent %s still waived after the group was revoked", a)
		}
	}
	if len(g.n.sent) != 1 {
		t.Errorf("%d notifications, want one for the group", len(g.n.sent))
	}
}

// TestT209_AnActiveGroupCannotBeWidened: once a group is ACTIVE no member
// row can join it, whether written as its member or copying it with
// another agent; a row may not differ from its group; and its member count
// is fixed.
// Covers: F602
func TestT209_AnActiveGroupCannotBeWidened(t *testing.T) {
	g := newGroupFixture(t)
	author := g.as(g.alice, tenancy.CredAccessToken, td.RolePolicyAuthor)
	group, _, err := g.svc.RequestGroup(author, g.groupRequest())
	if err != nil {
		t.Fatal(err)
	}
	// While pending, a row that waives something else than the group is
	// refused by the database.
	err = g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations,
			reason, owner_id, requested_by, requested_expiry, group_id)
			SELECT org_id, $2, bundle_id, rule_id, rule_digest, $3, ARRAY['payments.refund.approve'], reason, owner_id, requested_by,
				requested_expiry, id FROM pc.policy_exception_groups WHERE id = $1`, group.ID, ids.NewV7(), g.agent)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("a member waiving other operations: %v", err)
	}
	if err := g.approve(t, group.ID); err != nil {
		t.Fatal(err)
	}
	outsider := ids.NewV7()
	g.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'outsider', 'DISCOVERED', 'test')", g.org, outsider)
	err = g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations,
			reason, owner_id, requested_by, requested_expiry, group_id)
			SELECT org_id, $2, bundle_id, rule_id, rule_digest, $3, operations, reason, owner_id, requested_by, requested_expiry, id
			FROM pc.policy_exception_groups WHERE id = $1`, group.ID, ids.NewV7(), outsider)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("an agent joined an active group: %v", err)
	}
	// The app path refuses too: the member insert matches no pending group.
	err = g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := g.svc.ActivateGroup(ctx, tx, g.org, group.ID)
		return err
	})
	if !errors.Is(err, exceptions.ErrNotPending) {
		t.Fatalf("activating an active group again: %v", err)
	}
	// pc_app may not move a row out of its group or the group to another
	// cohort (no column grant), and the member count stays the snapshot's.
	for _, sql := range []string{
		"UPDATE pc.policy_exceptions SET group_id = NULL WHERE group_id = $1",
		"UPDATE pc.policy_exception_groups SET cohort_id = gen_random_uuid() WHERE id = $1",
	} {
		if err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, group.ID)
			return err
		}); !db.IsPermissionDenied(err) {
			t.Errorf("%s: %v", sql, err)
		}
	}
	if err := g.p.InTenantTx(context.Background(), g.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.policy_exception_groups SET members = 50 WHERE id = $1", group.ID)
		return err
	}); !db.IsCheckViolation(err) {
		t.Errorf("an active group's count was changed: %v", err)
	}
	if n := g.count(t, "SELECT members FROM pc.policy_exception_groups WHERE id = $1", group.ID); n != 2 {
		t.Errorf("the member count became %d", n)
	}
	if x := g.activeFor(t, outsider); len(x) != 0 {
		t.Fatal("the outsider is waived")
	}
}

// TestHR477_GroupsNeedEnterpriseAndAKnownCohort: a group is refused below
// Enterprise, for an unknown cohort and from an API key; a downgrade
// keeps an approved group in force, and revoking it works on every
// edition (D161).
// Covers: F602
func TestHR477_GroupsNeedEnterpriseAndAKnownCohort(t *testing.T) {
	g := newGroupFixture(t)
	author := g.as(g.alice, tenancy.CredAccessToken, td.RolePolicyAuthor)
	g.svc.Editions = edition(billing.Team)
	if _, _, err := g.svc.RequestGroup(author, g.groupRequest()); !errors.Is(err, exceptions.ErrGroupEdition) {
		t.Fatalf("a Team request: %v", err)
	}
	g.svc.Editions = nil
	if _, _, err := g.svc.RequestGroup(author, g.groupRequest()); !errors.Is(err, exceptions.ErrGroupEdition) {
		t.Fatalf("a request without an edition source: %v", err)
	}
	g.svc.Editions = edition(billing.Enterprise)
	if _, _, err := g.svc.RequestGroup(g.as(g.alice, tenancy.CredAPIKey, td.RolePolicyAuthor), g.groupRequest()); !errors.Is(err, exceptions.ErrHumanOnly) {
		t.Fatalf("an API key asked: %v", err)
	}
	r := g.groupRequest()
	r.Cohort = ids.NewV7()
	if _, _, err := g.svc.RequestGroup(author, r); !errors.Is(err, exceptions.ErrCohortNotFound) {
		t.Fatalf("an unknown cohort: %v", err)
	}
	if n := g.count(t, "SELECT count(*) FROM pc.policy_exception_groups"); n != 0 {
		t.Fatalf("%d groups stored by refused requests", n)
	}
	group, _, err := g.svc.RequestGroup(author, g.groupRequest())
	if err != nil {
		t.Fatal(err)
	}
	if err := g.approve(t, group.ID); err != nil {
		t.Fatal(err)
	}
	g.svc.Editions = edition(billing.Community)
	if len(g.activeFor(t, g.agent)) != 1 {
		t.Fatal("a downgrade dropped an approved group")
	}
	if _, err := g.svc.RevokeGroup(g.as(g.bob, tenancy.CredAccessToken, td.RolePolicyPublisher), group.ID, "done"); err != nil {
		t.Fatalf("revoking on Community: %v", err)
	}
}

// TestTenancy_policy_exception_groups: another org neither reads, writes
// nor joins an org's exception groups (00220, RLS).
// Covers: F602
func TestTenancy_policy_exception_groups(t *testing.T) {
	g := newGroupFixture(t)
	group, _, err := g.svc.RequestGroup(g.as(g.alice, tenancy.CredAccessToken, td.RolePolicyAuthor), g.groupRequest())
	if err != nil {
		t.Fatal(err)
	}
	other := ids.New[ids.Org]()
	g.d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)
	ctx := context.Background()
	var n int
	if err := g.p.InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.policy_exception_groups").Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("another org reads %d groups (%v)", n, err)
	}
	if err := g.p.InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.policy_exception_groups (org_id, id, cohort_id, bundle_id, rule_id, rule_digest, operations,
			reason, owner_id, requested_by, requested_expiry) VALUES ($1, $2, $3, 'refunds', 'hold-large', $4, ARRAY['a.b'], 'x', $5, $5,
			now() + interval '1 day')`, g.org, ids.NewV7(), g.cohort, make([]byte, 32), g.alice)
		return err
	}); err == nil {
		t.Error("another org wrote into the org's groups")
	}
	if err := g.p.InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
		tag, err := tx.Exec(ctx, "UPDATE pc.policy_exception_groups SET state = 'DECLINED' WHERE id = $1", group.ID)
		if err == nil && tag.RowsAffected() != 0 {
			return errors.New("updated")
		}
		return err
	}); err != nil {
		t.Errorf("another org changed a group: %v", err)
	}
	if _, err := g.svc.GetGroup(tenancy.WithCaller(ctx, tenancy.Caller{
		Subject: td.Subject{
			Org:       other,
			Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
			Bindings:  []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: other.UUID()}}},
		},
		Credential: tenancy.CredAccessToken,
	}), group.ID); !errors.Is(err, exceptions.ErrGroupNotFound) {
		t.Errorf("another org read the group: %v", err)
	}
}
