// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// An optional param in the dedupe key is null when the action leaves it
// out, which no value equals: a share to one person and a share to
// anyone, or a send with and without copies, are different actions. A
// required field without a value is still ambiguous (HR-007, G0 M31
// D1208).
func TestHR007_AnAbsentOptionalParamIsNullInTheDedupeKey(t *testing.T) {
	d := richDefinition()
	p := d.Params["branch"]
	p.Material = true
	d.Params["branch"] = p
	d.Dedupe = append(slices.Clone(d.Dedupe), "params.branch")
	target := actionir.Target{Type: "payments.charge", ID: "ch_1"}
	const base = `"amount":{"value":"30.00","currency":"USD"},"reason":"duplicate"`
	key := func(raw string) string {
		t.Helper()
		v, err := decode(t, d, raw)
		if err != nil {
			t.Fatal(err)
		}
		k, err := d.DedupeKey(target, v)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	absent, main, dev := key(`{`+base+`}`), key(`{`+base+`,"branch":"main"}`), key(`{`+base+`,"branch":"dev"}`)
	if absent == main || absent == dev {
		t.Fatal("an absent optional param must give a key no value gives")
	}
	if main == dev {
		t.Fatal("two values must give two keys")
	}
	if again := key(`{` + base + `}`); again != absent {
		t.Fatal("the same absent param must give the same key")
	}
	v, err := decode(t, d, `{`+base+`,"branch":"main"}`)
	if err != nil {
		t.Fatal(err)
	}
	delete(v, "amount")
	if _, err := d.DedupeKey(target, v); !errors.Is(err, actionir.ErrAmbiguous) {
		t.Fatalf("a missing required field: %v", err)
	}
}
