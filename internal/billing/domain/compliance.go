// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// ComplianceFramework reports whether the edition reads and exports a
// framework's coverage (G0 M25 D311): OWASP ASI and NIST AI RMF on Team and
// above; the EU AI Act, ISO 42001 and SOC 2 on Business and above. An unknown
// framework is never available.
func (e Entitlements) ComplianceFramework(framework string) bool {
	switch framework {
	case "OWASP_ASI", "NIST_AI_RMF":
		return e.Edition.Paid()
	case "EU_AI_ACT_DEPLOYER", "ISO_42001", "SOC2":
		return e.businessPlus()
	}
	return false
}
