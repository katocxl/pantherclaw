// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"connectrpc.com/connect/v2"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/policy/adapters/policiesrpc"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
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
// ports and the change requests (PUBLISH registered). Without a validator
// or a test runner nothing is published (fail closed).
func newPolicyVersions(pool *db.Pool, notify policyapp.Notifier, publicURL string) *policyapp.Versions {
	defs := &defspg.Store{Pool: pool}
	facts := &factspg.Store{Pool: pool}
	v := &policyapp.Versions{
		Store: &polpg.Store{Pool: pool}, Facts: facts, Subjects: facts, Definitions: defs,
		Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits,
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
