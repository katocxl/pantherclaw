// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "gateway.". The ledger stores each as "audit." + the kind.
const (
	GatewayBrokerKeyRegistered = "gateway.broker_key_registered"
	GatewayCertificateRevoked = "gateway.certificate_revoked"
	GatewayCreated = "gateway.created"
	GatewayEnrolled = "gateway.enrolled"
	GatewayEnrollmentIssued = "gateway.enrollment_issued"
	GatewayFleetPolicySet = "gateway.fleet_policy_set"
	GatewayRenewed = "gateway.renewed"
	GatewayRevoked = "gateway.revoked"
)
