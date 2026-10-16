// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

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

// wireM11Worker gives a worker-only process's core what the API wires in
// a combined one (D109 E1): grants and runs services whose store and
// service run govern's promotion gate, so automation issuance from the
// jobs is gated, and protect's compromised-publisher check.
func wireM11Worker(core *automationsCore, pool *db.Pool) {
	if core == nil || core.svc == nil {
		return
	}
	if core.grants == nil {
		gstore, grants := newGrants(pool)
		core.attach(pool, grants, runsapp.New(pool).WithGrants(gstore))
	}
	if core.svc.Compromise == nil {
		core.svc.Compromise = &protect.Publishers{Pool: pool}
	}
}
