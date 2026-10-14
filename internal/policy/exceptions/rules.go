// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exceptions

import (
	"crypto/sha256"
	"encoding/json/v2"

	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TODO(M11.1 S1a): replace with pdomain.Rule.Exceptable and
// pdomain.RuleDigest once the policy core is merged. Until then no rule is
// exceptable, so no exception can be requested (fail closed).
func exceptable(pdomain.Rule) bool { return false }

func ruleDigest(r pdomain.Rule) [32]byte {
	raw, _ := json.Marshal(r, json.Deterministic(true))
	return sha256.Sum256(raw)
}
