// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"strings"
	"testing"
)

// HR-234: a requirement without gate deciders prints as it did before
// gates, so recordings replay byte-identical; a gate's deciders print.
func TestHR234_NonGateRequirementsPrintAsBefore(t *testing.T) {
	r := Requirement{Kind: KindApproval, Role: "approver", Count: 1, Sources: []Source{}}
	if got := fmt.Sprintf("%+v", []Requirement{r}); got != "[{Kind:approval Role:approver Count:1 Independent:false Subject: Method: Sources:[] IndependentOf: Window:false}]" {
		t.Fatalf("non-gate requirement: %s", got)
	}
	g := GateRequirement(1, []string{"automation_operator"}, nil, nil)
	if got := fmt.Sprintf("%+v", g); !strings.Contains(got, "Roles:[automation_operator]") {
		t.Fatalf("gate requirement: %s", got)
	}
}
