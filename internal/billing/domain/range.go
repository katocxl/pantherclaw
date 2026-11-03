// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// RangeReports reports whether the edition exports signed assurance
// reports and gates on a baseline (G0 M12, PN-009, F4: Team and above).
// Community runs the engine and gets an unsigned summary.
func (e Entitlements) RangeReports() bool { return e.Edition.Paid() }

// RangeFullLibrary reports whether the edition runs the whole scenario
// library, business-tier scenarios included (G0 M12, F4: Business and
// above).
func (e Entitlements) RangeFullLibrary() bool {
	return e.Edition == Business || e.Edition == Enterprise
}

// RangeCustomScenarios reports whether the edition runs customer-authored
// CX-### scenarios (G0 M17 D126, PN-009.6: Business and above).
func (e Entitlements) RangeCustomScenarios() bool { return e.businessPlus() }

// AgentCampaigns reports whether the edition runs attack campaigns against a
// range twin of the customer's agent (G0 M25 D309: Business and above).
func (e Entitlements) AgentCampaigns() bool { return e.businessPlus() }
