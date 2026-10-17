// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Expected returns what an extended verifier must observe for an action on
// target with values vals: each expectation's JSON pointer and the text of
// the canonical field it names, as a target reports it (an identifier or
// enum as written, an integer in decimal, money as its value with the
// currency's minor-unit digits or its currency code). It returns false when
// a field it needs has no value, so the action cannot be verified as
// required (HR-191).
func (v *VerifierSpec) Expected(target actionir.Target, vals Values) (map[string]string, bool) {
	out := make(map[string]string, len(v.Expect))
	for _, e := range v.Expect {
		s, ok := referenceText(e.Equals, target, vals)
		if !ok {
			return nil, false
		}
		out[e.Field] = s
	}
	return out, true
}

func referenceText(ref string, target actionir.Target, vals Values) (string, bool) {
	switch ref {
	case "target.id":
		return target.ID, target.ID != ""
	case "target.account":
		return target.Account, target.Account != ""
	}
	rest, ok := strings.CutPrefix(ref, "params.")
	if !ok {
		return "", false
	}
	name, part, _ := strings.Cut(rest, ".")
	v, ok := vals[name]
	if !ok {
		return "", false
	}
	switch v.Type {
	case TypeMoney:
		switch part {
		case "value":
			return FormatMoney(v.Money), true
		case "currency":
			return string(v.Money.Currency), true
		case "minor":
			// What a target reports in integer minor units (G0 M14 D8).
			n, err := money.ToMinor(v.Money)
			return n, err == nil
		}
	case TypeInteger:
		return strconv.FormatInt(v.Int, 10), part == ""
	case TypeDecimal:
		return v.Decimal.String(), part == ""
	case TypeBoolean:
		return strconv.FormatBool(v.Bool), part == ""
	case TypeEnum, TypeIdentifier:
		return v.Str, part == ""
	case TypeIdentifierList, TypeText, TypeCommand, TypeContent, TypePath, TypeQueryFilter:
		// Lists and filters have no single value; text, commands, content
		// and paths are never compared with what a target reports.
	}
	return "", false
}
