// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/hex"
	"slices"
	"time"
)

// Exception is an active policy exception as the Authority reads it in a
// decision's snapshot (G0 M11.1 D14, HR-235): it waives rule Rule of
// bundle Bundle, as the rule was when the exception was requested
// (RuleDigest, hex), for the agent the decision is about and the listed
// exact operations, until ExpiresAt by the database clock.
type Exception struct {
	ID         string    `json:"id"`
	Bundle     string    `json:"bundle"`
	Rule       string    `json:"rule"`
	RuleDigest string    `json:"rule_digest"`
	Operations []string  `json:"operations"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Waivers returns, by rule id, the exception that waives each rule of b for
// an action on operation: a rule is waived only when the exception names
// b's bundle, the rule is exceptable in b, its digest is the one the
// exception names (a changed rule is not waived), and the operation is
// listed exactly. When several exceptions qualify for one rule, the
// lowest id wins, so the choice is deterministic. The exceptions are the
// agent's active ones; nil when none applies.
func Waivers(b *Bundle, operation string, xs []Exception) map[string]string {
	if b == nil || len(xs) == 0 {
		return nil
	}
	var out map[string]string
	for i := range b.Rules {
		r := &b.Rules[i]
		if !r.Exceptable {
			continue
		}
		d := RuleDigest(*r)
		digest := hex.EncodeToString(d[:])
		for _, x := range xs {
			if x.Bundle != b.ID || x.Rule != r.ID || x.RuleDigest != digest || !slices.Contains(x.Operations, operation) {
				continue
			}
			if cur, ok := out[r.ID]; ok && cur <= x.ID {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[r.ID] = x.ID
		}
	}
	return out
}
