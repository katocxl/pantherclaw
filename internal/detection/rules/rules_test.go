// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rules_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
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
