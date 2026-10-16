// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/protect"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// Cross-stream wiring no single M11 stream holds (G0 M11 part 2 D92, D96):
// the top branch pairs one stream's port with another stream's adapter.

// promotionsCompromise lets protect's compromised-publisher list refuse a
// compromised person's promotion (D43, D93 L1), in the promotion's
// transaction.
type promotionsCompromise struct{ p *protect.Publishers }

var _ promotions.CompromiseChecker = promotionsCompromise{}

func (c promotionsCompromise) Compromised(ctx context.Context, tx db.TenantTx, org ids.OrgID, user ids.UUID) (bool, error) {
	return c.p.Compromised(ctx, tx.Pgx(), org, user)
}

// m11Probe, when a test sets it, receives each M11 instance the server
// builds, by kind (TestM11_WiringComplete, D96); nil in production.
var m11Probe func(kind string, v any)

func probeM11(kind string, v any) {
	if m11Probe != nil {
		m11Probe(kind, v)
	}
}

// wireM11Cross wires the cross-stream pairs onto the API's instances.
func wireM11Cross(d apiDeps, prom *promotions.Service) {
	if pub := d.m11protect.publishers; pub != nil && prom != nil {
		prom.Compromise = promotionsCompromise{p: pub}
	}
	probeM11("promotions", prom)
}

// attachM11Issuance builds the process's one grants and runs pair through
// govern's newGrants, so its store and service run the promotion gate, and
// attaches it to the process's one core before the role split (D113): the
// API, the jobs and a worker-only process issue through the same gated
// services, and no ungated fallback exists.
func attachM11Issuance(core *automationsCore, pool *db.Pool) {
	if core == nil || core.svc == nil || core.grants != nil {
		return
	}
	gstore, grants := newGrants(pool)
	core.attach(pool, grants, runsapp.New(pool).WithGrants(gstore))
}

// wireM11Process wires the cross-stream pairs of the process's own
// instances, in every role, before the role split: the gated grants and
// runs pair on the one core (D113), and protect's PromotionRevoker on
// govern's RevokePromotion, so a compromised publisher's promotion rolls
// back as the reviewer (D90 Q2). Their promotions are an exposure source
// (D116 U1).
func wireM11Process(core *automationsCore, p m11Protect, pool *db.Pool) {
	attachM11Issuance(core, pool)
	if p.publishers != nil {
		p.publishers.Undo[protect.ItemPromotion] = protect.PromotionUndo(promotionRevoker{s: newPromotions(pool)})
		if p.publishers.Sources == nil {
			p.publishers.Sources = map[string]protect.ExposureSource{}
		}
		p.publishers.Sources[protect.ItemPromotion] = exposedPromotions
	}
}

// exposedPromotions is the promotions a compromised person made since the
// time they are compromised from, still live, for review (D43, D116 U1).
func exposedPromotions(ctx context.Context, tx db.TenantTx, user ids.UUID, since time.Time) ([]protect.Item, error) {
	rows, err := dbq.New(tx).ExposedPromotions(ctx, tx.OrgID(), user, since)
	if err != nil {
		return nil, err
	}
	out := make([]protect.Item, 0, len(rows))
	for _, r := range rows {
		out = append(out, protect.Item{Kind: protect.ItemPromotion, ID: r.ItemID, Label: r.Label, At: r.At})
	}
	return out, nil
}

// m11Issuance is the grants and runs pair the API serves: the core's when
// the process attached one, else a fresh gated pair (apiHandler built on
// its own, in tests).
func m11Issuance(d apiDeps) (*grantsapp.Service, *runsapp.Service) {
	if d.autos != nil && d.autos.grants != nil && d.autos.runs != nil {
		return d.autos.grants, d.autos.runs
	}
	gstore, grants := newGrants(d.pool)
	return grants, runsapp.New(d.pool).WithGrants(gstore)
}

// promotionRevoker is protect's PromotionRevoker over govern's
// RevokePromotion: an exposed promotion's ROLLBACK revokes it as the
// reviewer (D90 Q2). A promotion already revoked or gone has nothing left
// to roll back, so the undo is idempotent (D112 X2).
type promotionRevoker struct{ s *promotions.Service }

var _ protect.PromotionRevoker = promotionRevoker{}

func (r promotionRevoker) RevokePromotion(ctx context.Context, id ids.UUID, reason string) error {
	_, err := r.s.RevokePromotion(ctx, id, reason)
	if errors.Is(err, promotions.ErrState) || errors.Is(err, promotions.ErrNotFound) {
		return nil
	}
	return err
}

// cohortBaselines is templates' draft_baseline COHORT_BASELINE source over
// govern's fleet cohorts (D115 R2b): the baseline of the one cohort with a
// baseline the agent belongs to, in the step's transaction (the step
// already authorized the read). No such cohort, or several, is the step's
// refusal (NO_BASELINE, COHORT_AMBIGUOUS).
type cohortBaselines struct{}

var _ securitysteps.CohortBaselines = cohortBaselines{}

func (cohortBaselines) CohortBaseline(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (securitysteps.Baseline, error) {
	ttx, err := db.AdoptTenantTx(ctx, tx, org)
	if err != nil {
		return securitysteps.Baseline{}, err
	}
	b, cohort, err := cohorts.BaselineForAgent(ctx, ttx, org, agent)
	if err != nil {
		return securitysteps.Baseline{}, err
	}
	return securitysteps.Baseline{
		Bounds: b.Bounds, Limits: b.Limits, TTLSeconds: b.TTLSeconds, Basis: "the baseline of fleet cohort " + cohort.String(),
	}, nil
}
