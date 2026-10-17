// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestHR302_ScopeRulesNeedTheTeamEdition: a version with a data scope rule
// is published only on the Team edition or above, and refused without an
// edition source; other versions need none (G0 M14 D11).
func TestHR302_ScopeRulesNeedTheTeamEdition(t *testing.T) {
	scoped := &domain.Bundle{Rules: []domain.Rule{{Kind: domain.Constrain, Constraint: &domain.Constraint{Kind: domain.DataClasses, Values: []string{"public"}}}}}
	plain := &domain.Bundle{Rules: []domain.Rule{{Kind: domain.Forbid}}}
	ctx := context.Background()
	if err := (&Versions{Editions: edition(billing.Team)}).checkScopeEdition(ctx, scoped); err != nil {
		t.Fatalf("team: %v", err)
	}
	for name, v := range map[string]*Versions{"community": {Editions: edition(billing.Community)}, "no source": {}} {
		if err := v.checkScopeEdition(ctx, scoped); !errors.Is(err, ErrDataScopeEdition) {
			t.Errorf("%s: %v", name, err)
		}
		if err := v.checkScopeEdition(ctx, plain); err != nil {
			t.Errorf("%s, no scope rule: %v", name, err)
		}
	}
}
