// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// TestHR175_OnlyLowRiskHoldsAreBatched (decision 9): a reversible action
// with one plain approver and a value at or below the org's ceiling; the
// ceiling unset means no batch approval.
func TestHR175_OnlyLowRiskHoldsAreBatched(t *testing.T) {
	one := []domain.Requirement{{Kind: domain.KindApproval, Role: "approver", Count: 1}}
	usd := func(s string) *money.Money { m, _ := money.ParseMoney(s, "USD"); return &m }
	ceilings := map[string]string{"USD": "100.00"}
	for name, c := range map[string]struct {
		reqs          []domain.Requirement
		reversibility string
		value         *money.Money
		ceilings      map[string]string
		want          string
	}{
		"low risk":         {one, "reversible", usd("100.00"), ceilings, ""},
		"irreversible":     {one, "irreversible", usd("1.00"), ceilings, domain.BatchNotReversible},
		"two people":       {[]domain.Requirement{{Kind: domain.KindApproval, Role: "approver", Count: 2}}, "reversible", usd("1.00"), ceilings, domain.BatchNotSingleApprover},
		"independent":      {[]domain.Requirement{{Kind: domain.KindApproval, Role: "approver", Count: 1, Independent: true}}, "reversible", usd("1.00"), ceilings, domain.BatchNotSingleApprover},
		"step-up":          {[]domain.Requirement{{Kind: domain.KindStepUp, Subject: "launcher"}}, "reversible", usd("1.00"), ceilings, domain.BatchNotSingleApprover},
		"no value":         {one, "reversible", nil, ceilings, domain.BatchNoValue},
		"over":             {one, "reversible", usd("100.01"), ceilings, domain.BatchOverCeiling},
		"other currency":   {one, "reversible", func() *money.Money { m, _ := money.ParseMoney("1.00", "EUR"); return &m }(), ceilings, domain.BatchOverCeiling},
		"no ceiling (off)": {one, "reversible", usd("1.00"), nil, domain.BatchOverCeiling},
	} {
		ok, why := domain.Batchable(c.reqs, c.reversibility, c.value, c.ceilings)
		if ok != (c.want == "") || why != c.want {
			t.Errorf("%s: %v %s, want %q", name, ok, why, c.want)
		}
	}
}
