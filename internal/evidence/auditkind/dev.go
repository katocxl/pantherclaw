// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "dev.". The ledger stores each as "audit." + the kind.
const (
	DevGatewaySeeded  = "dev.gateway_seeded"
	DevOrgSeeded      = "dev.org_seeded"
	DevWorkloadSeeded = "dev.workload_seeded"
)
