// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "detection.". The ledger stores each as "audit." + the kind.
const (
	DetectionCustomRuleConfirmationRequested = "detection.custom_rule.confirmation_requested"
	DetectionCustomRuleConfirmationWithdrawn = "detection.custom_rule.confirmation_withdrawn"
	DetectionCustomRuleConfirmed             = "detection.custom_rule.confirmed"
	DetectionRuleCreated                     = "detection.rule_created"
	DetectionRuleDisabled                    = "detection.rule_disabled"
	DetectionRuleEnabled                     = "detection.rule_enabled"
	DetectionRulePublished                   = "detection.rule_published"
)
