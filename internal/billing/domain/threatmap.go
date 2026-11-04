// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Threat map editions (G0 M28 D723, founder Q2 A and FQ1 A). The matrix, the
// technique pages, the gaps and the labels are read by a person in the
// console on every edition; these three gate the rest.

// ThreatMapExport reports whether the org exports its threat map: the
// Navigator layer, the signed pack, the posture source and the MCP tool
// (Team and above).
func (e Entitlements) ThreatMapExport() bool { return e.Edition.Paid() }

// ThreatMapHistory reports whether the org keeps a daily threat map history
// and is told when a lane drops (Business and above).
func (e Entitlements) ThreatMapHistory() bool { return e.businessPlus() }

// ThreatMapAPIReads reports whether the threat map may be read with an API
// key or an access token (pclaw, scripts, MCP): Team and above. A person
// signed in to the console reads it on every edition (FQ1 A).
func (e Entitlements) ThreatMapAPIReads() bool { return e.Edition.Paid() }
