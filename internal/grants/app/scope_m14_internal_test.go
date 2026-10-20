// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestHR302_DataScopeNeedsTheTeamEdition: a grant with a data scope is
// issued only on the Team edition or above, and refused without an edition
// source; a grant without one needs none (G0 M14 D11).
func TestHR302_DataScopeNeedsTheTeamEdition(t *testing.T) {
	scope := domain.Bounds{Scope: map[string]domain.ScopeBound{"shop.rows.read": {Classes: &domain.Match{IDs: []string{"public"}}}}}
	ctx := context.Background()
	for name, c := range map[string]struct {
		eds  Editions
		b    domain.Bounds
		want error
	}{
		"team":            {edition(billing.Team), scope, nil},
		"community":       {edition(billing.Community), scope, ErrDataScopeEdition},
		"no source":       {nil, scope, ErrDataScopeEdition},
		"no scope":        {edition(billing.Community), domain.Bounds{}, nil},
		"business, scope": {edition(billing.Business), scope, nil},
	} {
		s := &Service{Editions: c.eds}
		if err := s.checkScopeEdition(ctx, c.b); !errors.Is(err, c.want) && (c.want != nil || err != nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
