// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package celenv

import (
	"context"
	"testing"
)

// TestMinorMoney: minor_money(int, string) is the amount of that many
// minor units, and an evaluation error for a currency outside the
// minor-unit list or a negative count (G0 M14 D8).
func TestMinorMoney(t *testing.T) {
	e, err := New(DefaultLimits, nil)
	if err != nil {
		t.Fatal(err)
	}
	for src, want := range map[string]string{
		`minor_money(8550, "USD") == money("85.50", "USD")`: "true",
		`minor_money(1200, "JPY") == money("1200", "JPY")`:  "true",
		`minor_money(5, "EUR") < money("0.06", "EUR")`:      "true",
		`minor_money(8550, "usd") == money("85.50", "USD")`: "true",
		`minor_money(1200, "Jpy").currency() == "JPY"`:      "true",
	} {
		p, err := e.Compile(src, nil)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		v, _, err := p.Eval(context.Background(), map[string]any{})
		if err != nil || v.Value() != true {
			t.Errorf("%s = %v, %v (want %s)", src, v, err, want)
		}
	}
	for _, src := range []string{`minor_money(1500, "KWD")`, `minor_money(-1, "USD")`, `minor_money(1, "xyz")`, "minor_money(100, \"uſd\")", `minor_money(100, "usdx")`, `minor_money(100, "US")`} {
		p, err := e.Compile(src, nil)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if v, _, err := p.Eval(context.Background(), map[string]any{}); err == nil {
			t.Errorf("%s = %v", src, v)
		}
	}
}
