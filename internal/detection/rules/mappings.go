// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rules

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

// RetiredATLAS holds the ATLAS ids earlier releases listed that the pinned
// ATLAS release dropped, among them every id of the list rules accepted
// before the pinned catalog (G0 M28 D711, D711a): they stay accepted so
// stored custom rules keep parsing, and the threat-map closure test refuses
// them in PantherClaw's own mappings (D715).
var RetiredATLAS = map[string]bool{
	"AML.T0019": true, "AML.T0024.000": true, "AML.T0024.001": true, "AML.T0024.002": true,
	"AML.T0056": true, "AML.T0057": true, "AML.T0058": true, "AML.T0104": true,
}

// owaspRisks is the closed list of OWASP Top 10 for Agentic Applications
// (2026) risks.
var owaspRisks = []string{"ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"}

// KnownATLAS reports whether id is an ATLAS technique or sub-technique of
// the pinned catalog, or a retired one (D711).
func KnownATLAS(id string) bool { return catalog.KnownATLAS(id) || RetiredATLAS[id] }

// KnownATTACK reports whether id is an ATT&CK Enterprise technique or
// sub-technique of the pinned catalog (D711).
func KnownATTACK(id string) bool { return catalog.KnownATTACK(id) }

// KnownOWASP reports whether id is a listed OWASP agentic risk.
func KnownOWASP(id string) bool { return slices.Contains(owaspRisks, id) }
