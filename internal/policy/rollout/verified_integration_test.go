// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package rollout_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e), Status: billing.StatusValid}, nil
}

// publishGate stands in for the publish gate (D6): Publish publishes at
// once, calling the rollout's hook in its transaction as the real gate
// does; its validation and change requests are tested elsewhere.
type publishGate struct {
	svc       *rollout.Service
	pool      *db.Pool
	org       ids.OrgID
	published int
}

func (g *publishGate) CheckPilot(context.Context, ids.UUID, ids.UUID, *ids.UUID, []rollout.RolloutCohort) (*rollout.ChangeRequest, error) {
	return nil, nil //nolint:nilnil // the pilot starts now
}

func (g *publishGate) Publish(ctx context.Context, version ids.UUID, base *ids.UUID) (*rollout.ChangeRequest, error) {
	err := g.pool.InTenantTx(ctx, g.org, func(ctx context.Context, tx db.TenantTx) error {
		var b ids.UUID
		if base != nil {
			b = *base
		}
		return g.svc.Published(ctx, tx, g.org, version, &b)
	})
	if err == nil {
		g.published++
	}
	return nil, err
}

type gateWorld struct {
	d            *dbtest.DB
	p            *db.Pool
	org          ids.OrgID
	pat          ids.UUID
	base, draft  ids.UUID
	agents       []ids.UUID
	svc          *rollout.Service
	gate         *publishGate
	publisherCtx context.Context
}

func newGateWorld(t *testing.T) *gateWorld {
	t.Helper()
	d := dbtest.New(t)
	w := &gateWorld{d: d, p: d.AppPool(t), org: ids.New[ids.Org](), pat: ids.NewV7(), base: ids.NewV7(), draft: ids.NewV7()}
	w.svc = &rollout.Service{Pool: w.p, Editions: edition(billing.Enterprise)}
	w.gate = &publishGate{svc: w.svc, pool: w.p, org: w.org}
	w.svc.Gate = w.gate
	raw, err := json.Marshal(pdomain.Bundle{ID: "refunds", Version: 1}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	policy := ids.NewV7()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'gate')", w.org)
	d.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'pat')", w.org, w.pat)
	d.AdminExec(t, "INSERT INTO pc.policies (org_id, id, bundle_id) VALUES ($1, $2, 'refunds')", w.org, policy)
	d.AdminExec(t, `INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, state, created_by, published_by, published_at)
		VALUES ($1, $2, $3, 1, $4, 'PUBLISHED', 'test', 'test', now())`, w.org, w.base, policy, raw)
	d.AdminExec(t, `INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, state, created_by)
		VALUES ($1, $2, $3, 2, $4, 'DRAFT', 'test')`, w.org, w.draft, policy, raw)
	for range 4 {
		a := ids.NewV7()
		d.AdminExec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'test')", w.org, a, "a-"+a.String()[30:])
		w.agents = append(w.agents, a)
	}
	w.publisherCtx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.pat},
			Bindings: []td.Binding{{Role: td.RolePolicyPublisher, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
		},
		Credential: tapp.CredAccessToken,
	})
	return w
}

// targets gives the rollout one target per agent, in the states given.
func (w *gateWorld) targets(t *testing.T, r ids.UUID, states ...string) {
	t.Helper()
	for i, s := range states {
		w.d.AdminExec(t, `INSERT INTO pc.policy_rollout_targets (org_id, rollout_id, agent_id, state) VALUES ($1, $2, $3, $4)
			ON CONFLICT (org_id, rollout_id, agent_id) DO UPDATE SET state = EXCLUDED.state`, w.org, r, w.agents[i], s)
	}
}

func (w *gateWorld) stage(t *testing.T, r ids.UUID) string {
	t.Helper()
	got, err := w.svc.GetRollout(w.publisherCtx, r)
	if err != nil {
		t.Fatal(err)
	}
	return got.Stage
}

func pct(n int32) *int32 { return &n }

// TestHR479_AGatedRolloutCompletesOnlyAtItsThreshold: a rollout started
// with a 100% threshold does not complete while a target other than
// EXCEPTION is not VERIFIED, whether through CompleteRollout, a publish
// of its version made another way, or a direct stage change; once every
// such target is VERIFIED it completes. An EXCEPTION target is not
// counted.
// Covers: F602
func TestHR479_AGatedRolloutCompletesOnlyAtItsThreshold(t *testing.T) {
	w := newGateWorld(t)
	r, err := w.svc.StartGatedRollout(w.publisherCtx, w.draft, nil, pct(100))
	if err != nil {
		t.Fatal(err)
	}
	if r.RequireVerifiedPercent == nil || *r.RequireVerifiedPercent != 100 {
		t.Fatalf("threshold %v", r.RequireVerifiedPercent)
	}
	// No target yet: never met.
	if _, _, err := w.svc.CompleteRollout(w.publisherCtx, r.ID); !errors.Is(err, rollout.ErrNotVerified) {
		t.Fatalf("completing with no targets: %v", err)
	}
	w.targets(t, r.ID, rollout.TargetVerified, rollout.TargetVerified, rollout.TargetFailed, rollout.TargetException)
	if _, _, err := w.svc.CompleteRollout(w.publisherCtx, r.ID); !errors.Is(err, rollout.ErrNotVerified) {
		t.Fatalf("completing with a FAILED target: %v", err)
	}
	if w.gate.published != 0 {
		t.Fatal("the version was published below the threshold")
	}
	// A publish of the version made any other way is refused too.
	if _, err := w.gate.Publish(w.publisherCtx, w.draft, &w.base); !errors.Is(err, rollout.ErrNotVerified) {
		t.Fatalf("a direct publish below the threshold: %v", err)
	}
	// And the database refuses the stage change itself.
	err = w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.policy_rollouts SET stage = 'COMPLETE', completed_at = now() WHERE id = $1", r.ID)
		return err
	})
	if !db.IsCheckViolation(err) {
		t.Fatalf("a direct stage change below the threshold: %v", err)
	}
	if s := w.stage(t, r.ID); s != rollout.StageShadow {
		t.Fatalf("stage %s, want SHADOW", s)
	}
	w.targets(t, r.ID, rollout.TargetVerified, rollout.TargetVerified, rollout.TargetVerified, rollout.TargetException)
	if _, _, err := w.svc.CompleteRollout(w.publisherCtx, r.ID); err != nil {
		t.Fatalf("completing at the threshold: %v", err)
	}
	if s := w.stage(t, r.ID); s != rollout.StageComplete || w.gate.published != 1 {
		t.Fatalf("stage %s after %d publishes", s, w.gate.published)
	}
}

// TestHR479_TheThresholdIsFixedAndOutlivesADowngrade: starting a gated
// rollout needs Enterprise and a threshold of 1 to 100; the threshold
// cannot be changed afterwards, and a downgrade does not drop it (D161).
// An ungated rollout completes as before.
// Covers: F602
func TestHR479_TheThresholdIsFixedAndOutlivesADowngrade(t *testing.T) {
	w := newGateWorld(t)
	for _, bad := range []int32{0, 101} {
		if _, err := w.svc.StartGatedRollout(w.publisherCtx, w.draft, nil, pct(bad)); !errors.Is(err, rollout.ErrVerifiedPercent) {
			t.Errorf("threshold %d: %v", bad, err)
		}
	}
	w.svc.Editions = edition(billing.Team)
	if _, err := w.svc.StartGatedRollout(w.publisherCtx, w.draft, nil, pct(50)); !errors.Is(err, rollout.ErrLargeFleetEdition) {
		t.Fatalf("a Team gated rollout: %v", err)
	}
	w.svc.Editions = edition(billing.Enterprise)
	r, err := w.svc.StartGatedRollout(w.publisherCtx, w.draft, nil, pct(75))
	if err != nil {
		t.Fatal(err)
	}
	err = w.p.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.policy_rollouts SET require_verified_percent = 1 WHERE id = $1", r.ID)
		return err
	})
	if !db.IsPermissionDenied(err) {
		t.Fatalf("lowering the threshold: %v", err)
	}
	w.svc.Editions = edition(billing.Community)
	w.targets(t, r.ID, rollout.TargetVerified, rollout.TargetVerified, rollout.TargetFailed, rollout.TargetAcknowledged)
	if _, _, err := w.svc.CompleteRollout(w.publisherCtx, r.ID); !errors.Is(err, rollout.ErrNotVerified) {
		t.Fatalf("after a downgrade, 50%% verified against 75%%: %v", err)
	}
	if _, err := w.svc.CancelRollout(w.publisherCtx, r.ID); err != nil {
		t.Fatal(err)
	}
	w.svc.Editions = edition(billing.Team)
	open, err := w.svc.StartRollout(w.publisherCtx, w.draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if open.RequireVerifiedPercent != nil {
		t.Fatal("an ungated rollout has a threshold")
	}
	if _, _, err := w.svc.CompleteRollout(w.publisherCtx, open.ID); err != nil {
		t.Fatalf("an ungated rollout with no targets: %v", err)
	}
}
