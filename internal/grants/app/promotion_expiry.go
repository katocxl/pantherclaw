// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// PromotionExpiry is implemented by a PromotionGate whose promotions can be
// PROVISIONAL (G0 M11 part 2 D80, founder decision F7): a grant standing on
// one ends with it, so Issue, Revise and automation issuance cap the
// grant's expiry at ProvisionalExpiry (nil: nothing to cap).
type PromotionExpiry interface {
	ProvisionalExpiry(ctx context.Context, org ids.OrgID, agent, env ids.UUID, ops domain.Ops) (*time.Time, error)
}

// capExpiry caps g's expiry at the earliest provisional promotion it
// stands on, when the gate has provisional promotions.
func (s *Service) capExpiry(ctx context.Context, org ids.OrgID, g *domain.Grant) error {
	pe, ok := s.Promotions.(PromotionExpiry)
	if !ok {
		return nil
	}
	var ops domain.Ops
	if g.Bounds.Operations != nil {
		ops = *g.Bounds.Operations
	}
	until, err := pe.ProvisionalExpiry(ctx, org, g.AgentID, g.EnvironmentID, ops)
	if err != nil || until == nil {
		return err
	}
	if g.ExpiresAt.IsZero() || g.ExpiresAt.After(*until) {
		g.ExpiresAt = *until
	}
	return nil
}
