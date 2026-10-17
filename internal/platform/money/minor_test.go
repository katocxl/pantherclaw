// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package money

import (
	"errors"
	"testing"
)

// TestMinorUnits: amounts go to and from integer minor units by the
// currency's exponent, only for the listed currencies, never rounded
// (G0 M14 D8).
func TestMinorUnits(t *testing.T) {
	for _, c := range []struct {
		units    int64
		currency Currency
		amount   string
	}{{8550, "USD", "85.5"}, {5, "EUR", "0.05"}, {0, "GBP", "0"}, {1200, "JPY", "1200"}, {7, "KRW", "7"}} {
		m, err := FromMinor(c.units, c.currency)
		if err != nil || m.Amount.String() != c.amount || m.Currency != c.currency {
			t.Errorf("FromMinor(%d, %s) = %v, %v", c.units, c.currency, m, err)
		}
		back, err := ToMinor(m)
		if err != nil || back != formatInt(c.units) {
			t.Errorf("ToMinor(%v) = %q, %v", m, back, err)
		}
	}
	for _, cur := range []Currency{"KWD", "BHD", "INR", "usd", "XXX"} {
		if _, err := FromMinor(1, cur); !errors.Is(err, ErrMinorCurrency) {
			t.Errorf("FromMinor in %s: %v", cur, err)
		}
	}
	if _, err := FromMinor(-1, "USD"); err == nil {
		t.Error("negative minor units")
	}
	kwd, _ := ParseMoney("1.500", "KWD")
	if _, err := ToMinor(kwd); !errors.Is(err, ErrMinorCurrency) {
		t.Errorf("ToMinor in KWD: %v", err)
	}
	neg, _ := ParseMoney("-1.00", "USD")
	if _, err := ToMinor(neg); err == nil {
		t.Error("a negative amount in minor units")
	}
}

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
