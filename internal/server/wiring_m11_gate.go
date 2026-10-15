// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/json/v2"

	"connectrpc.com/connect/v2"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/policiesrpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	"github.com/katocxl/pantherclaw/internal/policy/validate"
)

// policyGateExtensions let the other M11.1 streams hook into the publish
// gate from their own wiring files (rollouts set OnPublished and register
// ROLLOUT, exceptions register EXCEPTION): each runs once, on the server's
// policy versions, before anything is served.
var policyGateExtensions []func(d apiDeps, v *policyapp.Versions)

// registerPolicyGate serves PolicyService through the publish gate (G0
// M11.1 design decisions 6, 9 and 11; HR-230, HR-231, HR-236) and adds the
// policy changes pages, where people confirm a loosening with a security
// key, when security keys are configured.
func registerPolicyGate(rs *connect.Server, d apiDeps) {
	var notify policyapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	v := newPolicyVersions(d.pool, notify, d.publicURL)
	for _, ext := range policyGateExtensions {
		ext(d, v)
	}
	pantherclawv1connect.RegisterPolicyServiceHandler(rs, policiesrpc.New(v))
	if d.web != nil && d.m5 != nil && d.m5.webauthn != nil {
		d.web.WithPolicyChanges(v.Changes, d.m5.webauthn)
	}
}

// newPolicyVersions builds the policy versions use cases with the gate's
// ports (S1a's validator and scenario test runner, D7a) and the change
// requests (PUBLISH registered). Without a validator or a test runner the
// gate publishes nothing (fail closed).
func newPolicyVersions(pool *db.Pool, notify policyapp.Notifier, publicURL string) *policyapp.Versions {
	defs := &defspg.Store{Pool: pool}
	facts := &factspg.Store{Pool: pool}
	validator := validate.New(defs, facts, facts, celenv.DefaultLimits)
	validator.Approvers, validator.Sources = gateReaders{pool}, gateReaders{pool}
	v := &policyapp.Versions{
		Store: &polpg.Store{Pool: pool}, Facts: facts, Subjects: facts, Definitions: defs,
		Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits,
		Validator: validator, Tests: scenario.New(defs, facts, celenv.DefaultLimits, policyapp.DefaultBudget),
		Outcomes: outcomeDiff{validator},
	}
	v.Changes = policyapp.NewChanges(pool, notify, publicURL, currentPolicyDigests(defs, facts))
	v.Changes.Register(policyapp.ChangePublish, v.ApplyPublish)
	return v
}

// currentPolicyDigests are the digests of the org's active definitions and
// fact catalog now, as a test run records them (D7a).
func currentPolicyDigests(defs *defspg.Store, facts *factspg.Store) policyapp.CurrentDigests {
	return func(ctx context.Context, org ids.OrgID) ([32]byte, [32]byte, error) {
		ds, err := defs.ActiveDefinitions(ctx, org)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		catalog, err := facts.Catalog(ctx, org)
		if err != nil {
			return [32]byte{}, [32]byte{}, err
		}
		return pdomain.DefinitionsDigest(ds), pdomain.CatalogDigest(catalog), nil
	}
}

// outcomeDiff serves DiffPolicyVersions' sample outcome changes (D8) as
// JSON.
type outcomeDiff struct{ v *validate.Validator }

func (o outcomeDiff) OutcomeDiff(ctx context.Context, org ids.OrgID, base, next *pdomain.Bundle) ([]byte, error) {
	changes, err := o.v.OutcomeDiff(ctx, org, base, next)
	if err != nil {
		return nil, err
	}
	if changes == nil {
		changes = []validate.OutcomeChange{}
	}
	return json.Marshal(changes, json.Deterministic(true))
}

// gateReaders answer the validator's optional checks (D8): APPROVER_NONE
// (no active person holds a rule's approval role at the org) and
// FACT_NO_SOURCE (no active provider or connection supplies a fact).
type gateReaders struct{ pool *db.Pool }

func (r gateReaders) Approvers(ctx context.Context, org ids.OrgID, role string) (int, error) {
	var n int32
	err := r.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).PolicyRoleHolders(ctx, org, role)
		return err
	}, db.ReadOnly())
	return int(n), err
}

func (r gateReaders) SuppliedFacts(ctx context.Context, org ids.OrgID) (map[string]bool, error) {
	out := map[string]bool{}
	err := r.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		names, err := dbq.New(tx).PolicySuppliedFacts(ctx, org)
		for _, n := range names {
			out[n] = true
		}
		return err
	}, db.ReadOnly())
	return out, err
}
