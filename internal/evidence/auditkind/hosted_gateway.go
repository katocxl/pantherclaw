// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "hosted_gateway.". The ledger stores each as "audit." + the kind.
const (
	HostedGatewayDeprovisioned           = "hosted_gateway.deprovisioned"
	HostedGatewayFailed                  = "hosted_gateway.failed"
	HostedGatewayProvisioned             = "hosted_gateway.provisioned"
	HostedGatewayRequested               = "hosted_gateway.requested"
	HostedGatewayServerCertificateIssued = "hosted_gateway.server_certificate_issued"
	HostedGatewayStopped                 = "hosted_gateway.stopped"
	HostedGatewayTokenPulled             = "hosted_gateway.token_pulled"
	HostedGatewayTokenReissued           = "hosted_gateway.token_reissued"
)
