// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Development fact provider: the refund definition needs a fresh
// payments.charge.refundable fact about the charge (a prerequisite).
const (
	devFact          = "payments.charge.refundable"
	devFactSubject   = "payments.charge"
	devGrantLifetime = 24 * time.Hour
)

// devPackage is a reference package dev seed imports.
type devPackage struct {
	Name, Version string
	Raw           []byte
}

// seedPackages imports reference packages into org and activates them. One
// metadata document lists them all, signed by signer (devPackageSigner): the
// development package key that local servers trust (HR-163), or a throwaway
// key trusted for this import only. The org records the signed metadata,
// never the key.
func seedPackages(ctx context.Context, pool *db.Pool, org ids.OrgID, signer *jws.Signer, pkgs ...devPackage) error {
	targets := map[string]trust.Target{}
	for _, p := range pkgs {
		sum := sha256.Sum256(p.Raw)
		targets[trust.Key(p.Name, p.Version)] = trust.Target{Length: int64(len(p.Raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}}
	}
	doc, err := trust.Sign(trust.Targets{
		Version: 1, Expires: time.Now().Add(180 * 24 * time.Hour).UTC().Format(time.RFC3339), Targets: targets,
	}, signer)
	if err != nil {
		return err
	}
	im := &defsapp.Importer{Roots: trust.Roots{signer.KeyID(): signer.Public()}, Repo: &defspg.Store{Pool: pool}, Clock: clock.System{}}
	for _, p := range pkgs {
		ev := &audit.Event{
			Name: "package.imported", Actor: devSeedActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "package_version", ID: trust.Key(p.Name, p.Version)},
		}
		if _, err := im.Import(ctx, org, p.Name, p.Version, doc, p.Raw, ev); err != nil {
			return fmt.Errorf("dev seed: package %s: %w", p.Name, err)
		}
		act := &audit.Event{
			Name: "package.transitioned", Actor: devSeedActor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "package_version", ID: trust.Key(p.Name, p.Version)},
			Details: map[string]string{"from": string(defs.StateReviewed), "to": string(defs.StateActive)},
		}
		if err := im.Transition(ctx, org, p.Name, p.Version, defs.StateActive, act); err != nil {
			return fmt.Errorf("dev seed: activate package %s: %w", p.Name, err)
		}
	}
	return nil
}

// seedFacts registers a development fact provider for refundable charges,
// bound to a new service account, and returns an API key that lets it
// report facts (fact.write only).
func seedFacts(ctx context.Context, pool *db.Pool, org ids.OrgID, env credential.Env) (credential.Token, error) {
	sa := ids.NewV7()
	key, err := credential.New(credential.APIKey, env, org)
	if err != nil {
		return key, err
	}
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.InsertServiceAccount(ctx, dbq.InsertServiceAccountParams{
			OrgID: org, ID: sa, Name: "dev-billing", Description: "development fact provider (dev seed)", CreatedBy: "dev-seed",
		}); err != nil {
			return err
		}
		if _, err := q.InsertRoleBinding(ctx, dbq.InsertRoleBindingParams{
			OrgID: org, ID: ids.NewV7(), Role: "fact_provider", ServiceAccountID: &sa, ScopeType: "ORG", CreatedBy: "dev-seed",
		}); err != nil {
			return err
		}
		_, err := q.InsertAPIKey(ctx, dbq.InsertAPIKeyParams{
			OrgID: org, ID: ids.NewV7(), ServiceAccountID: sa, Name: "dev-facts", SecretHash: key.Hash(), Hint: key.Hint(),
			Scopes: []string{"fact.write"}, CreatedBy: "dev-seed", TtlDays: 30,
		})
		return err
	})
	if err != nil {
		return key, fmt.Errorf("dev seed: fact provider account: %w", err)
	}
	p := fdomain.Provider{
		ID: ids.NewV7(), Org: org, Name: "dev.billing", ServiceAccountID: sa, State: fdomain.ProviderActive,
		Facts: []fdomain.Declaration{{Name: devFact, Type: fdomain.TypeBoolean, SubjectType: devFactSubject, MaxLag: 5 * time.Minute}},
	}
	if err := p.Validate(func(string) bool { return false }); err != nil {
		return key, err
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: devSeedActor, Outcome: audit.Success,
		Object: &audit.Object{Type: "fact_provider", ID: p.ID.String()}, Details: map[string]string{"service_account": sa.String()},
	}
	if err := (&factspg.Store{Pool: pool}).CreateProvider(ctx, org, p, "operator:dev-seed", ev); err != nil {
		return key, fmt.Errorf("dev seed: fact provider: %w", err)
	}
	return key, nil
}

// devGrantTerms are the terms of the grant dev seed issues.
type devGrantTerms struct {
	MaxPerAction money.Money // per refund
	Limit        money.Money // the task budget
	MaxCount     int         // 0: no count limit
	// Shell also allows shell commands (pc.shell, the Claude Code hook).
	Shell bool
	// GitHub also allows the pc.github operations: a merge needs an
	// independent code_reviewer, the deployment it may start a
	// release_approver (inside a change window, HR-207), and a task merges
	// once (G0 M8, §43).
	GitHub bool
	// Stripe also allows the pc.stripe operations: refunds, charges and
	// transfers up to 100.00 USD each, one refund per task (G0 M14 D14).
	Stripe bool
	// StripePayee is the connected account the grant may transfer to.
	StripePayee string
	// Postgres also allows the pc.postgres reads (G0 M14 D21).
	Postgres bool
	// A2A also allows the pc.a2a operations: messages to the peer agent,
	// whose runs this grant delegates to (G0 M14 D33).
	A2A bool
}

// seedGrant issues a root grant to the seeded agent for its owner: refunds
// up to the per-action maximum, a task budget, and one level of
// delegation. It is checked like any issuance against the org's active
// definitions; dev seed is the grantor of record (no person signs in for
// the seeded owner).
func seedGrant(ctx context.Context, pool *db.Pool, org ids.OrgID, w devWorkload, t devGrantTerms) (gdomain.Grant, error) {
	ops := []string{"payments.refund.create", "payments.refund.get"}
	if t.Shell {
		ops = append(ops, shellOperation)
	}
	if t.GitHub {
		ops = append(ops, githubOperations...)
	}
	params := map[string]any{"payments.refund.create": map[string]any{
		"amount": map[string]any{"max": map[string]string{string(t.MaxPerAction.Currency): t.MaxPerAction.Amount.String()}},
	}}
	var stripeBudget map[string]any
	var stripeDests []string
	if t.Stripe {
		var stripeOps []string
		var stripeParams map[string]any
		stripeOps, stripeParams, stripeBudget, stripeDests = stripeGrant(t.StripePayee)
		ops = append(ops, stripeOps...)
		maps.Copy(params, stripeParams)
	}
	if t.Postgres {
		ops = append(ops, postgresOperations...)
	}
	if t.A2A {
		ops = append(ops, devA2AOperations...)
	}
	doc := map[string]any{"operations": ops, "params": params}
	if stripeDests != nil {
		// Transfers go only to the seeded payee; actions without a
		// destination are not limited by it.
		doc["destinations"] = map[string]any{"ids": stripeDests}
	}
	bounds, err := json.Marshal(doc)
	if err != nil {
		return gdomain.Grant{}, err
	}
	budget := map[string]any{
		"id": "task", "grouping": "task", "operations": []string{"payments.refund.create"},
		"currency": string(t.Limit.Currency), "limit": t.Limit.Amount.String(), "period": "none",
	}
	if t.MaxCount > 0 {
		budget["max_count"] = fmt.Sprint(t.MaxCount)
	}
	budgets := []any{budget}
	if t.GitHub {
		budgets = append(budgets, map[string]any{
			"id": "merges", "grouping": "task", "operations": []string{"github.pull.merge"}, "max_count": "1", "period": "none",
		})
	}
	if stripeBudget != nil {
		budgets = append(budgets, stripeBudget)
	}
	limits, err := json.Marshal(map[string]any{"budgets": budgets})
	if err != nil {
		return gdomain.Grant{}, err
	}
	b, err := gdomain.DecodeBounds(bounds)
	if err != nil {
		return gdomain.Grant{}, err
	}
	lim, err := gdomain.DecodeLimits(limits)
	if err != nil {
		return gdomain.Grant{}, err
	}
	now := time.Now()
	g := gdomain.Grant{
		ID: gdomain.NewGrantID(), Org: org, Revision: 1, State: gdomain.StateActive,
		AgentID: w.Agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.Owner}, EnvironmentID: w.Env,
		TaskRef: "dev seed", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(devGrantLifetime), Bounds: b, Limits: lim,
		Delegation: gdomain.Delegation{Depth: 1, MaxChildren: 5},
		Grantor:    gdomain.Principal{Kind: gdomain.PrincipalUser, ID: w.Owner}, Basis: "issued by pantherclaw-server dev seed",
	}
	if t.GitHub {
		g.Requirements = []gdomain.Requirement{
			{
				Operations: gdomain.Ops{"github.pull.merge"}, Reason: "MERGES_NEED_AN_INDEPENDENT_REVIEW",
				Approval: &pdomain.ApprovalRequirement{Role: "code_reviewer", Count: 1, Independent: true},
			},
			{
				Operations: gdomain.Ops{"github.deployment.trigger"}, Reason: "DEPLOYMENTS_NEED_A_RELEASE",
				Approval: &pdomain.ApprovalRequirement{Role: "release_approver", Count: 1},
			},
		}
	}
	if t.Stripe {
		g.Requirements = append(g.Requirements, stripeRequirement())
	}
	defsStore := &defspg.Store{Pool: pool}
	active := map[string]*defs.Definition{}
	for _, op := range append(append(append([]string{"payments.refund.create", shellOperation}, githubOperations...), stripeOperations...), devA2AOperations...) {
		if (op == shellOperation && !t.Shell) || (slices.Contains(githubOperations, op) && !t.GitHub) || (slices.Contains(stripeOperations, op) && !t.Stripe) ||
			(slices.Contains(devA2AOperations, op) && !t.A2A) {
			continue
		}
		d, err := defsStore.Active(ctx, org, op)
		if err != nil {
			return gdomain.Grant{}, err
		}
		active[op] = d
	}
	lookup := func(op string) *defs.Definition { return active[op] }
	if err := g.ValidateIssue(gdomain.IssueContext{Now: now, Lookup: lookup}); err != nil {
		return gdomain.Grant{}, fmt.Errorf("dev seed: grant: %w", err)
	}
	ev := audit.Event{
		Name: "grant.issued", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "grant", ID: g.ID.String()},
		Details: map[string]string{"agent": w.Agent.String(), "principal": g.Principal.String()},
	}
	if err := (&grantspg.Store{Pool: pool}).Issue(ctx, org, &g, ev); err != nil {
		return gdomain.Grant{}, fmt.Errorf("dev seed: grant: %w", err)
	}
	return g, nil
}

// writeSecretFile writes s to a new 0600 file (never overwritten).
func writeSecretFile(path, s string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: operator-chosen path
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, s+"\n"); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
