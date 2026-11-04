// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "security.". The ledger stores each as "audit." + the kind.
const (
	SecurityActionTampered            = "security.action_tampered"
	SecurityDiscoveryFlood            = "security.discovery_flood"
	SecurityEffectWithoutReceipt      = "security.effect_without_receipt"
	SecurityEnrollmentTokenReused     = "security.enrollment_token_reused"
	SecurityEvidenceIntegrityFailed   = "security.evidence_integrity_failed"
	SecurityGatewayEnrollmentReused   = "security.gateway_enrollment_reused"
	SecurityInstanceNetworkChanged    = "security.instance_network_changed"
	SecurityKillSwitchEngaged         = "security.kill_switch_engaged"
	SecurityKillSwitchRestoreCanceled = "security.kill_switch_restore_canceled"
	SecurityKillSwitchRestoreProposed = "security.kill_switch_restore_proposed"
	SecurityKillSwitchRestored        = "security.kill_switch_restored"
	SecurityStripeLivemode            = "security.stripe_livemode"
	SecurityVariantSuspected          = "security.variant_suspected"
)
