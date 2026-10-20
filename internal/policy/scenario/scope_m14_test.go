// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scenario

import (
	"bytes"
	"os"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// scopedWorld is newWorld with refund reads that enforce a data scope.
func scopedWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	raw, err := os.ReadFile(pipelinetest.PackagePath())
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("  - operation: payments.refund.get\n    summary: Read one refund\n    access: read\n"),
		[]byte("  - operation: payments.refund.get\n    summary: Read one refund\n    access: read\n    scoping: [records, classes]\n"), 1)
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w.defs = nil
	for i := range pkg.Definitions {
		w.defs = append(w.defs, &pkg.Definitions[i])
	}
	return w
}

// TestM14_ScenarioCasesEnforceDataScope: a scenario case runs a scoping
// read through a route the gateway reads (a pantherclaw_held http
// connection), so a data_classes rule or a grant's record scope is an
// obligation (ALLOW_WITH_OBLIGATIONS), while a definition without scoping,
// reached through the SDK, is still SCOPE_UNSUPPORTED (G0 M14 D108).
func TestM14_ScenarioCasesEnforceDataScope(t *testing.T) {
	read := func(id string, expect pdomain.TestExpect) pdomain.TestCase {
		return pdomain.TestCase{
			ID: id, Summary: "read a refund",
			Action: pdomain.TestAction{Operation: "payments.refund.get", Target: &actionir.Target{Type: "payments.refund", ID: "re_1"}},
			Expect: expect,
		}
	}
	obliged := pdomain.TestExpect{Decision: "ALLOW_WITH_OBLIGATIONS", Reason: "DATA_SCOPE"}
	byRule := pdomain.TestExpect{Decision: "ALLOW_WITH_OBLIGATIONS", Reason: "NO_PII", Rule: "no-pii"}
	classes := pdomain.Rule{
		ID: "no-pii", Kind: pdomain.Constrain, Summary: "no pii in refund reads", Operations: []string{"payments.refund.get", refund},
		When: "true", Reason: "NO_PII", Constraint: &pdomain.Constraint{Kind: pdomain.DataClasses, Values: []string{"public", "internal"}},
	}
	records := read("records", obliged)
	records.Given = &pdomain.TestGiven{Grant: &pdomain.TestGrant{Constraints: []pdomain.Constraint{
		{Kind: pdomain.RecordScope, Param: "customer", Values: []string{"cus_1"}},
	}}}
	sdk := refundCase("sdk", "10.00", pdomain.TestExpect{Decision: "CANNOT_AUTHORIZE", Reason: "SCOPE_UNSUPPORTED"})
	onCreate := pdomain.Rule{
		ID: "refund-public", Kind: pdomain.Constrain, Summary: "refund answers public only", Operations: []string{refund},
		When: "true", Reason: "REFUND_PUBLIC", Constraint: &pdomain.Constraint{Kind: pdomain.DataClasses, Values: []string{"public"}},
	}
	for name, b := range map[string]*pdomain.Bundle{
		"rule":  bundle([]pdomain.Rule{classes}, read("classes", byRule)),
		"grant": bundle([]pdomain.Rule{onCreate}, records, sdk),
	} {
		res := runOK(t, newRunner(scopedWorld(t), papp.DefaultBudget), b)
		for _, c := range res.Cases {
			if !c.Passed {
				t.Errorf("%s case %s: %s", name, c.ID, c.Detail)
			}
		}
		if len(res.Cases) != len(b.Tests) {
			t.Fatalf("%s cases %+v", name, res.Cases)
		}
	}
}
