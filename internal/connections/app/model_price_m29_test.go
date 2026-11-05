// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e), Status: billing.StatusValid}, nil
}

// TestHR698_AModelPriceNeedsTeam: a price on a model connection is set on
// Team and above; Community, or no edition source, refuses it; a model
// connection without a price needs no edition (G0 M29 D811, D829).
//
// Covers: F987, HR-698
func TestHR698_AModelPriceNeedsTeam(t *testing.T) {
	priced := &ModelConfig{Price: &ModelPrice{Currency: "USD", Input: "3", Output: "15"}}
	for _, e := range []billing.Edition{billing.Team, billing.Business, billing.Enterprise} {
		if err := (&Service{ents: edition(e)}).checkModelPrice(t.Context(), priced); err != nil {
			t.Errorf("%s: %v", e, err)
		}
		if !(billing.Entitlements{Edition: e}).TokenCostReports() {
			t.Errorf("%s has no cost reports", e)
		}
	}
	for name, s := range map[string]*Service{"community": {ents: edition(billing.Community)}, "no edition source": {}} {
		if err := s.checkModelPrice(t.Context(), priced); !errors.Is(err, ErrModelPriceEdition) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := (&Service{ents: edition(billing.Community)}).checkModelPrice(t.Context(), &ModelConfig{MaxOutputTokens: 100}); err != nil {
		t.Errorf("no price on community: %v", err)
	}
	if billing.CommunityEntitlements().TokenCostReports() {
		t.Error("community has cost reports")
	}
}

// TestT318_APriceIsTheOrganizationsOwnAndChecked: a price needs a known
// currency and non-negative decimals; there is no default price.
//
// Covers: HR-698
func TestT318_APriceIsTheOrganizationsOwnAndChecked(t *testing.T) {
	m, err := ModelConfig{}.Check()
	if err != nil || m.Price != nil || m.MaxOutputTokens != DefaultModelMaxOutputTokens {
		t.Fatalf("defaults = %+v, %v", m, err)
	}
	for _, p := range []ModelPrice{
		{Currency: "XXX", Input: "1", Output: "1"},
		{Currency: "USD", Input: "-1", Output: "1"},
		{Currency: "USD", Input: "1"},
		{Currency: "USD", Input: "1", Output: "1", CacheRead: "x"},
		{Input: "1", Output: "1"},
	} {
		if _, err := (ModelConfig{Price: &p}).Check(); !errors.Is(err, ErrModelConfig) {
			t.Errorf("%+v: %v", p, err)
		}
	}
}
