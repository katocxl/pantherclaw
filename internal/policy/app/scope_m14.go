// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// ErrDataScopeEdition: a policy version with a data scope rule needs the
// Team edition or above to publish (G0 M14 D11). Rules already published
// keep being enforced after a downgrade.
var ErrDataScopeEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"data scope rules need the Team edition or above")

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// checkScopeEdition refuses to publish a bundle with a data scope rule
// unless the edition offers data scoping; without an edition source it
// refuses (fail closed).
func (v *Versions) checkScopeEdition(ctx context.Context, b *domain.Bundle) error {
	if !b.HasScopeRules() {
		return nil
	}
	if v.Editions == nil {
		return ErrDataScopeEdition
	}
	e, err := v.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.DataScoping() {
		return ErrDataScopeEdition
	}
	return nil
}
