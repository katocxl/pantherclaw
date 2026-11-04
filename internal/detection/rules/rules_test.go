// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rules_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

const base = `id: org.watch
version: "1"
title: Watch
description: Watches.
severity: LOW
attention: ALERT
basis: OBSERVED
edition: business
on: [audit.x.y]
tests: []
`

// TestRuleIDsAndMappingsAreBounded: rule ids fit the 128-byte columns
// (D59 H3) and ATLAS / OWASP mappings come from the closed lists (L11).
func TestRuleIDsAndMappingsAreBounded(t *testing.T) {
	if _, err := rules.Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	long := "org.a" + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60)
	for name, src := range map[string]string{
		"long id":       strings.Replace(base, "org.watch", long, 1),
		"unknown ATLAS": base + "atlas: [AML.T9999]\n",
		"unknown OWASP": base + "owasp: [ASI11]\n",
		"PAGE custom":   strings.Replace(base, "attention: ALERT", "attention: PAGE", 1),
	} {
		if _, err := rules.Parse([]byte(src)); !errors.Is(err, rules.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !rules.KnownATLAS("AML.T0051.001") || rules.KnownATLAS("AML.T0051.009") || !rules.KnownOWASP("ASI10") {
		t.Error("closed lists")
	}
}

const builtinBase = `id: pc.test.watch
version: "1"
title: Watch
description: Watches.
severity: LOW
attention: ALERT
basis: OBSERVED
edition: community
on: [audit.x.y]
tests: []
`

// Covers: F974, HR-682
func TestHR682_RuleMappingsComeFromThePinnedCatalogue(t *testing.T) {
	for name, src := range map[string]string{
		"ATT&CK technique":       base + "attack: [T1059]\n",
		"ATT&CK sub-technique":   base + "attack: [T1059.001]\n",
		"ATLAS from the catalog": base + "atlas: [AML.T0051.000]\n",
		"retired ATLAS id":       base + "atlas: [AML.T0057]\n",
		"built-in, none":         builtinBase + "techniques_none: A live view of activity, not a detection.\n",
		"built-in, mapped":       builtinBase + "attack: [T1078]\natlas: [AML.T0051]\n",
	} {
		if _, err := rules.Parse([]byte(src)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, src := range map[string]string{
		"unknown ATT&CK":       base + "attack: [T9999]\n",
		"ATLAS id as ATT&CK":   base + "attack: [AML.T0051]\n",
		"ATT&CK id as ATLAS":   base + "atlas: [T1059]\n",
		"too many ATT&CK":      base + "attack: [" + strings.TrimSuffix(strings.Repeat("T1059, ", 17), ", ") + "]\n",
		"custom says none":     base + "techniques_none: Not a detection.\n",
		"built-in both":        builtinBase + "attack: [T1078]\ntechniques_none: Not a detection.\n",
		"built-in neither":     builtinBase,
		"none on two lines":    builtinBase + "techniques_none: \"one\\ntwo\"\n",
		"none blank":           builtinBase + "techniques_none: \"  \"\n",
		"none longer than 200": builtinBase + "techniques_none: " + strings.Repeat("a", 201) + "\n",
	} {
		if _, err := rules.Parse([]byte(src)); !errors.Is(err, rules.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !rules.KnownATTACK("T1078.004") || rules.KnownATTACK("T1078.999") {
		t.Error("KnownATTACK")
	}
}

// Covers: F974, HR-682, HR-683
func TestHR682_RetiredATLASIdsAreOnlyThoseThePinnedCatalogueLacks(t *testing.T) {
	if len(rules.RetiredATLAS) == 0 {
		t.Fatal("no retired ids")
	}
	for id := range rules.RetiredATLAS {
		if catalog.Known(id) {
			t.Errorf("%s is in the pinned catalog, so it is not retired", id)
		}
		if !rules.KnownATLAS(id) {
			t.Errorf("%s: a retired id stays accepted", id)
		}
	}
	// Every id of the closed list rules accepted before the pinned
	// catalog (G0 M10 D9, as published in 2025) is still known.
	for _, id := range preCatalogATLAS {
		if !rules.KnownATLAS(id) {
			t.Errorf("%s was accepted before the catalog and must stay so", id)
		}
	}
}

// preCatalogATLAS is the hand list internal/detection/rules/mappings.go held
// before G0 M28 D711.
var preCatalogATLAS = []string{
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
