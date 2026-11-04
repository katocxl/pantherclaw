// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "consequence_rule.". The ledger stores each as "audit." + the kind.
const (
	ConsequenceRuleActivated = "consequence_rule.activated"
	ConsequenceRuleProposed  = "consequence_rule.proposed"
	ConsequenceRuleRetired   = "consequence_rule.retired"
)
