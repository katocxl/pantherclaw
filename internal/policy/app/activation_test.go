// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

type published struct{ b *domain.Bundle }

func (p published) PublishedInTx(context.Context, db.TenantTx, ids.OrgID) (*domain.Bundle, error) {
	return p.b, nil
}

type factCatalog map[string]fdomain.Type

func (c factCatalog) CatalogInTx(context.Context, db.TenantTx, ids.OrgID) (map[string]fdomain.Type, error) {
	return c, nil
}

// TestAnActivationThatBreaksThePublishedPolicyIsRefused (G0 M4,
// policy compilation): a rule on an operation no active package defines
// compiles without that definition. When an activation would define it so
// that the rule no longer type-checks, the activation is refused, instead
// of every later decision failing closed on a policy that does not
// compile. A policy that still compiles, or no policy, lets it through.
func TestAnActivationThatBreaksThePublishedPolicyIsRefused(t *testing.T) {
	f := newFixture(t)
	refund := f.def("payments.refund.create")
	broken := &domain.Bundle{ID: "org-policy", Version: 3, Rules: []domain.Rule{
		refundRule("no-big-tips", domain.Forbid, `action.params.tip > money("10.00", "USD")`),
	}}
	ok := &domain.Bundle{ID: "org-policy", Version: 4, Rules: []domain.Rule{
		refundRule("no-large-refunds", domain.Forbid, `action.params.amount > money("1000.00", "USD")`),
	}}
	check := func(b *domain.Bundle, active ...*defs.Definition) error {
		return ActivationCheck{Policies: published{b}, Facts: factCatalog{}, Limits: celenv.DefaultLimits}.
			CheckActivation(context.Background(), db.TenantTx{}, active)
	}
	if err := check(broken); err != nil {
		t.Fatalf("without the definition the rule compiles: %v", err)
	}
	err := check(broken, refund)
	if pcerr.ReasonOf(err) != ReasonPackageBreaksPolicy {
		t.Fatalf("an activation after which the published policy does not compile: %v", err)
	}
	if pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Fatalf("the refusal is a failed precondition: %v", err)
	}
	if err := check(ok, refund); err != nil {
		t.Fatalf("a policy that still compiles: %v", err)
	}
	if err := check(nil, refund); err != nil {
		t.Fatalf("no published policy: %v", err)
	}
}
