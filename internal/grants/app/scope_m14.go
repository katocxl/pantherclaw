// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// ErrDataScopeEdition: a grant that limits data scope needs the Team
// edition or above (G0 M14 D11). Scope already in force keeps being
// enforced after a downgrade; only new and revised grants are refused.
var ErrDataScopeEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"limiting the data a grant may read needs the Team edition or above")

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// checkScopeEdition refuses bounds with a data scope unless the edition
// offers data scoping; without an edition source it refuses (fail closed).
func (s *Service) checkScopeEdition(ctx context.Context, b domain.Bounds) error {
	if !b.HasScope() {
		return nil
	}
	if s.Editions == nil {
		return ErrDataScopeEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.DataScoping() {
		return ErrDataScopeEdition
	}
	return nil
}
