// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"fmt"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// ReasonCurrencyMismatch: a binding compares money in two currencies
// (G0 M14 D48).
const ReasonCurrencyMismatch = "CURRENCY_MISMATCH"

// bindingAtMost checks an le binding (G0 M14 D48): the param is at most
// the fact's member, money of one currency (another currency is
// CANNOT_AUTHORIZE CURRENCY_MISMATCH) or integers. A member that is
// missing or of another type fails with the binding's reason.
func (s *state) bindingAtMost(pr defs.Prerequisite) bool {
	b := pr.Binds
	want := s.vals[b.Param]
	member := memberOf(s.facts[pr.Fact], b.Member)
	fail := func(reason, detail string) bool {
		s.cl.add(StepFacts, adomain.CannotAuthorize, reason, detail, "")
		return false
	}
	switch want.Type { //nolint:exhaustive // only money and integers compare with le (validated)
	case defs.TypeMoney:
		have, ok := member.(map[string]any)
		m, isMoney := memberMoney(have)
		switch {
		case !ok || !isMoney:
			return fail(b.Reason, fmt.Sprintf("%s.%s is not an amount", pr.Fact, b.Member))
		case m.Currency != want.Money.Currency:
			return fail(ReasonCurrencyMismatch, fmt.Sprintf("params.%s is in %s, but %s.%s is in %s",
				b.Param, want.Money.Currency, pr.Fact, b.Member, m.Currency))
		}
		if c, err := want.Money.Cmp(m); err != nil || c > 0 {
			return fail(b.Reason, fmt.Sprintf("params.%s is %s, more than %s.%s, %s", b.Param, want.Money, pr.Fact, b.Member, m))
		}
		return true
	case defs.TypeInteger:
		have, ok := member.(int64)
		if !ok || want.Int > have {
			return fail(b.Reason, fmt.Sprintf("params.%s is %d, more than %s.%s, %s", b.Param, want.Int, pr.Fact, b.Member,
				memberValue(s.facts[pr.Fact], b.Member)))
		}
		return true
	}
	return fail(b.Reason, "params."+b.Param+" cannot be compared")
}

// memberOf is a member of an object fact, or nil.
func memberOf(f fdomain.Value, member string) any {
	if f.Object == nil {
		return nil
	}
	return f.Object[member]
}

// memberMoney reads an amount member, {"value": "85.50", "currency": "USD"}
// in its canonical form, as an action's money param is written.
func memberMoney(v map[string]any) (money.Money, bool) {
	value, ok1 := v["value"].(string)
	currency, ok2 := v["currency"].(string)
	if !ok1 || !ok2 || len(v) != 2 {
		return money.Money{}, false
	}
	m, err := money.ParseMoney(value, currency)
	if err != nil || defs.FormatMoney(m) != value {
		return money.Money{}, false
	}
	return m, true
}
