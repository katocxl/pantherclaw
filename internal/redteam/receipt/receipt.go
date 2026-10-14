// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package receipt reads which explanation evidence a decision receipt carries
// (the check.receipt step, D33). Both range drivers use it, so a scenario
// means the same thing under either.
package receipt

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
)

// Fields are the names a check.receipt step may ask for.
var Fields = []string{"grant", "policy_version", "package_version", "facts", "simulated"}

// Parts reads a decision receipt (a compact JWS whose payload holds the
// decision's claims under "pap") and reports each of Fields as present or
// not: grant (the guardrail levels the grant chain was checked against),
// policy_version (basis.policy), package_version (basis.definition), facts
// (basis.facts) and simulated (pap.simulated is true). A receipt that cannot
// be read has none of them.
func Parts(compact string) map[string]bool {
	out := map[string]bool{}
	segs := strings.Split(compact, ".")
	if len(segs) != 3 {
		return out
	}
	raw, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return out
	}
	var claims struct {
		Pap struct {
			Basis struct {
				Policy     string           `json:"policy"`
				Definition string           `json:"definition"`
				Facts      string           `json:"facts"`
				Levels     []jsontext.Value `json:"levels"`
			} `json:"basis"`
			Simulated bool `json:"simulated"`
		} `json:"pap"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return out
	}
	b := claims.Pap.Basis
	out["grant"] = len(b.Levels) > 0
	out["policy_version"] = b.Policy != "" && b.Policy != "none"
	out["package_version"] = b.Definition != ""
	out["facts"] = b.Facts != ""
	out["simulated"] = claims.Pap.Simulated
	return out
}

// Missing returns the wanted fields a receipt does not carry, in order.
func Missing(compact string, want []string) []string {
	have := Parts(compact)
	var missing []string
	for _, w := range want {
		if !have[w] {
			missing = append(missing, w)
		}
	}
	return missing
}
