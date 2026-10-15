// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rules

import "slices"

// atlasTechniques is the closed list of MITRE ATLAS technique and
// sub-technique ids a rule may map to (D9, D59 L11), as published in 2025.
// A new ATLAS release adds ids here.
var atlasTechniques = []string{
	"AML.T0000", "AML.T0001", "AML.T0002", "AML.T0002.000", "AML.T0002.001", "AML.T0003", "AML.T0004",
	"AML.T0005", "AML.T0005.000", "AML.T0005.001", "AML.T0005.002", "AML.T0006", "AML.T0007",
	"AML.T0008", "AML.T0008.000", "AML.T0008.001", "AML.T0008.002", "AML.T0008.003", "AML.T0008.004",
	"AML.T0010", "AML.T0010.000", "AML.T0010.001", "AML.T0010.002", "AML.T0010.003",
	"AML.T0011", "AML.T0011.000", "AML.T0011.001", "AML.T0012", "AML.T0013", "AML.T0014", "AML.T0015",
	"AML.T0016", "AML.T0016.000", "AML.T0016.001", "AML.T0017", "AML.T0017.000", "AML.T0018", "AML.T0018.000",
	"AML.T0018.001", "AML.T0019", "AML.T0020", "AML.T0021", "AML.T0024", "AML.T0024.000", "AML.T0024.001",
	"AML.T0024.002", "AML.T0025", "AML.T0029", "AML.T0031", "AML.T0034", "AML.T0035", "AML.T0036", "AML.T0037",
	"AML.T0040", "AML.T0041", "AML.T0042", "AML.T0043", "AML.T0043.000", "AML.T0043.001", "AML.T0043.002",
	"AML.T0043.003", "AML.T0043.004", "AML.T0044", "AML.T0046", "AML.T0047", "AML.T0048", "AML.T0048.000",
	"AML.T0048.001", "AML.T0048.002", "AML.T0048.003", "AML.T0048.004", "AML.T0049", "AML.T0050", "AML.T0051",
	"AML.T0051.000", "AML.T0051.001", "AML.T0052", "AML.T0052.000", "AML.T0053", "AML.T0054", "AML.T0055",
	"AML.T0056", "AML.T0057", "AML.T0058", "AML.T0059", "AML.T0060", "AML.T0061", "AML.T0062", "AML.T0063",
	"AML.T0064", "AML.T0065", "AML.T0066", "AML.T0067", "AML.T0068", "AML.T0069", "AML.T0069.000",
	"AML.T0069.001", "AML.T0069.002", "AML.T0070", "AML.T0071", "AML.T0072", "AML.T0073", "AML.T0074",
	"AML.T0075", "AML.T0076", "AML.T0077", "AML.T0078", "AML.T0079", "AML.T0080", "AML.T0080.000",
	"AML.T0080.001", "AML.T0081", "AML.T0082", "AML.T0083", "AML.T0084", "AML.T0084.000", "AML.T0084.001",
	"AML.T0084.002", "AML.T0085", "AML.T0085.000", "AML.T0085.001", "AML.T0086",
}

// owaspRisks is the closed list of OWASP Top 10 for Agentic Applications
// (2026) risks.
var owaspRisks = []string{"ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "ASI10"}

// KnownATLAS reports whether id is a listed ATLAS technique.
func KnownATLAS(id string) bool { return slices.Contains(atlasTechniques, id) }

// KnownOWASP reports whether id is a listed OWASP agentic risk.
func KnownOWASP(id string) bool { return slices.Contains(owaspRisks, id) }
