// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/protect"
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

// wireM11Cross wires the cross-stream pairs onto the API's instances.
func wireM11Cross(d apiDeps, prom *promotions.Service) {
	if pub := d.m11protect.publishers; pub != nil && prom != nil {
		prom.Compromise = promotionsCompromise{p: pub}
	}
}
