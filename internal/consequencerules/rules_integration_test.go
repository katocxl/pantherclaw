// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package consequencerules_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/consequencerules"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// requests is an in-memory change ceremony.
type requests struct {
	mu     sync.Mutex
	opened map[ids.UUID]protect.Request
}

func (r *requests) Open(_ context.Context, _ db.TenantTx, q protect.Request) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := ids.NewV7()
	r.opened[id] = q
	return id, nil
}

func (r *requests) Void(context.Context, db.TenantTx, ids.UUID, string) error { return nil }

func (r *requests) Pending(context.Context, db.TenantTx, ids.UUID) (bool, error) { return true, nil }

// edition is the org's edition.
type edition struct{ e bdomain.Edition }

func (x edition) Current(context.Context) (bdomain.Entitlements, error) {
	return bdomain.Entitlements{Edition: x.e}, nil
}

// github serves pc.github's definitions as the org's ACTIVE ones.
type github struct{ p *defs.Package }

func (g github) ActiveInTx(_ context.Context, _ db.TenantTx, _ ids.OrgID, op string) (*defs.Package, *defs.Definition, error) {
	if d, ok := g.p.Definition(op); ok {
		return g.p, d, nil
	}
	return nil, nil, nil
}

type env struct {
	pool          *db.Pool
	org           ids.OrgID
	gate          *protect.Gate
	svc           *consequencerules.Service
	author, other ids.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	p, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), org: ids.New[ids.Org](), author: ids.NewV7(), other: ids.NewV7()}
	e.gate = &protect.Gate{Requests: &requests{opened: map[ids.UUID]protect.Request{}}}
	e.svc = (&consequencerules.Service{Pool: e.pool, Editions: edition{bdomain.Team}, Definitions: github{p}}).WithProtect(e.gate)
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'rules')", e.org)
	for _, u := range []ids.UUID{e.author, e.other} {
		e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, u, u.String())
		e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			e.org, ids.NewV7(), string(td.RoleSecurityAdmin), u)
	}
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) as(user ids.UUID) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession})
}

// confirm applies the change of request as confirmed by user.
func (e *env) confirm(request, user ids.UUID) error {
	return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, request, []ids.UUID{user})
	})
}

func (e *env) active(t *testing.T) []dbq.PcCustomerConsequenceRule {
	t.Helper()
	var out []dbq.PcCustomerConsequenceRule
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).ActiveCustomerConsequenceRules(ctx, e.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func rule() defs.ConsequenceRule {
	return defs.ConsequenceRule{
		ID: "cx.merge-pages", Operation: "github.pull.merge", When: "facts.github_repo_deploy_triggers.state != 'none'",
		RequiresFacts: []string{"github.repo.deploy_triggers"}, ValidUntil: "2027-10-11",
		Consequence: defs.Consequence{
			Operation: "github.deployment.trigger", Effect: "deployment.trigger", Target: "{target.id.owner}/{target.id.repo}",
			Description: "A merge deploys and pages on-call",
		},
	}
}

// TestHR453_ACustomerRuleTakesTwoPeople: proposing a rule stores it
// PROPOSED and opens a protected change with CONSEQUENCE_RULES off; its
// author cannot confirm it, a second person can, and the rule is then
// ACTIVE with them as its approver; retiring it is a protected change
// too. A rule whose operation is not an ACTIVE definition, or a Community
// org, proposes nothing.
//
// Covers: F405, F413
func TestHR453_ACustomerRuleTakesTwoPeople(t *testing.T) {
	e := newEnv(t)
	v, held, err := e.svc.Propose(e.as(e.author), rule())
	if err != nil || held == nil || v.State != consequencerules.StateProposed || v.Version != 1 {
		t.Fatalf("propose: %v %+v %+v", err, held, v)
	}
	if len(e.active(t)) != 0 {
		t.Fatal("ACTIVE before a second person confirmed it")
	}
	if err := e.confirm(held.Request, e.author); !errors.Is(err, protect.ErrState) {
		t.Fatalf("confirmed by its author: %v", err)
	}
	if err := e.confirm(held.Request, e.other); err != nil {
		t.Fatal(err)
	}
	a := e.active(t)
	if len(a) != 1 || a[0].ID != v.ID || a[0].ApprovedBy == nil || *a[0].ApprovedBy != e.other || a[0].ProposedBy != e.author {
		t.Fatalf("active: %+v", a)
	}

	// A second version replaces the first once confirmed.
	v2, held2, err := e.svc.Propose(e.as(e.other), rule())
	if err != nil || v2.Version != 2 {
		t.Fatalf("second version: %v %+v", err, v2)
	}
	if err := e.confirm(held2.Request, e.author); err != nil {
		t.Fatal(err)
	}
	if a := e.active(t); len(a) != 1 || a[0].Version != 2 {
		t.Fatalf("after the second version: %+v", a)
	}

	retire, err := e.svc.Retire(e.as(e.author), "cx.merge-pages")
	if err != nil || retire == nil {
		t.Fatalf("retire: %v %+v", err, retire)
	}
	if len(e.active(t)) != 1 {
		t.Fatal("retired before a second person confirmed it")
	}
	if err := e.confirm(retire.Request, e.other); err != nil {
		t.Fatal(err)
	}
	if a := e.active(t); len(a) != 0 {
		t.Fatalf("after retiring: %+v", a)
	}
	if _, err := e.svc.Retire(e.as(e.author), "cx.merge-pages"); !errors.Is(err, consequencerules.ErrNotActive) {
		t.Fatalf("retire again: %v", err)
	}

	bad := rule()
	bad.Consequence.Operation = "github.nothing.here"
	if _, _, err := e.svc.Propose(e.as(e.author), bad); !errors.Is(err, consequencerules.ErrInvalid) {
		t.Fatalf("an operation that is not ACTIVE: %v", err)
	}
	e.svc.Editions = edition{bdomain.Community}
	if _, _, err := e.svc.Propose(e.as(e.author), rule()); !errors.Is(err, consequencerules.ErrEdition) {
		t.Fatalf("Community: %v", err)
	}
}
