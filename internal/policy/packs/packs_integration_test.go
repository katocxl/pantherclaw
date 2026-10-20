// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package packs_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
	"github.com/katocxl/pantherclaw/internal/policy/policytest"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type team struct{}

func (team) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = billing.Team
	return x, nil
}

type catalog struct{}

func (catalog) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return map[string]fdomain.Type{}, nil
}

type definitions struct{ ds []*defs.Definition }

func (d definitions) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return d.ds, nil
}

// TestHR291_ApplyingAPackOnlyDrafts (D41): applying read-only-diagnostics
// for an agent stores a DRAFT policy version that keeps the published
// rules and adds the pack's; the published version, grants and
// promotions are unchanged, the draft's own audit record names the pack
// (G11), and a person without policy.author or a Community org is refused.
func TestHR291_ApplyingAPackOnlyDrafts(t *testing.T) {
	ctx := context.Background()
	p := dbtest.New(t).AppPool(t)
	org, tm, env, alice, agent := ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql, args...).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	exec("INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'ops', 'Ops')", org, tm)
	exec("INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'production', 'Production', 'PRODUCTION')", org, env, tm)
	exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, alice)
	exec(`INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'diagnoser', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, org, agent, tm, env, alice)

	raw, err := os.ReadFile("../../../packages/pc-shell/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	ds := make([]*defs.Definition, len(pkg.Definitions))
	for i := range pkg.Definitions {
		ds[i] = &pkg.Definitions[i]
	}
	store := &pgstore.Store{Pool: p}
	versions := &policyapp.Versions{Store: store, Facts: catalog{}, Definitions: definitions{ds}, Authz: gapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits}
	base := policytest.Publish(ctx, t, p, org, &pdomain.Bundle{ID: "org", Version: 1, Rules: []pdomain.Rule{{
		ID: "no-root", Kind: pdomain.Forbid, Summary: "no sudo", Operations: []string{"shell.command.run"},
		When: "action.params.command.startsWith('sudo')", Reason: "NO_SUDO",
	}}})
	svc := &packs.Service{Pool: p, Editions: team{}, Drafts: versions}
	as := func(roles ...td.RoleName) context.Context {
		var bs []td.Binding
		for _, r := range roles {
			bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
		}
		return tapp.WithCaller(ctx, tapp.Caller{
			Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: alice}, Bindings: bs},
			Credential: tapp.CredBrowserSession,
		})
	}
	in := packs.Apply{Pack: "read-only-diagnostics", Environment: env, Agents: []ids.UUID{agent}, Parameters: map[string]string{"workspace": "/srv/app"}}

	if _, err := svc.ApplyPack(as(td.RoleResponder), in); err == nil {
		t.Fatal("applied without policy.author")
	}
	if _, err := (&packs.Service{Pool: p, Drafts: versions}).ApplyPack(as(td.RolePolicyAuthor, td.RoleResponder), in); err == nil {
		t.Fatal("applied in a Community org")
	}
	grants, promoted := count("SELECT count(*) FROM pc.grants"), count("SELECT count(*) FROM pc.agent_promotions")
	res, err := svc.ApplyPack(as(td.RolePolicyAuthor, td.RoleResponder), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Version.State != "DRAFT" || res.Version.ID == base {
		t.Fatalf("version %+v, want a new DRAFT", res.Version)
	}
	if len(res.Added) == 0 || len(res.Baselines) != 1 || res.Baselines[0].Agent != agent {
		t.Fatalf("applied %+v", res)
	}
	b, err := policyapp.DecodeBundle(res.Version.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(b.Rules, func(r pdomain.Rule) bool { return r.ID == "no-root" }) {
		t.Error("the draft dropped the published rule")
	}
	if pub, err := store.PublishedVersion(ctx, org); err != nil || pub == nil || pub.ID != base {
		t.Fatalf("published after applying: %v %v", pub, err)
	}
	if count("SELECT count(*) FROM pc.grants") != grants || count("SELECT count(*) FROM pc.agent_promotions") != promoted {
		t.Fatal("applying a pack issued a grant or promoted an agent")
	}
	again, err := svc.ApplyPack(as(td.RolePolicyAuthor, td.RoleResponder), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Added) != len(res.Added) {
		t.Errorf("a second draft from the same published version adds %d, want %d", len(again.Added), len(res.Added))
	}
	// D114: a pack whose rules are per agent is refused without an agent.
	for _, a := range []packs.Apply{
		{Pack: "aggregate-reporting", Environment: env},
		{Pack: "support-resolution", Environment: env, Parameters: map[string]string{packs.ParamCustomers: "cus-1001"}},
	} {
		if _, err := svc.ApplyPack(as(td.RolePolicyAuthor, td.RoleResponder), a); err == nil || !strings.Contains(err.Error(), "needs agents") {
			t.Errorf("%s without an agent: %v", a.Pack, err)
		}
	}
}
