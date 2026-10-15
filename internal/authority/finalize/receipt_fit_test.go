// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
)

// TestHR235_AnOversizedReceiptKeepsItsWaivedItems (F2, D33): a decision
// that used a policy exception names it in its receipt, so trimming an
// oversized receipt keeps every WAIVED item, as it keeps the decisive one.
func TestHR235_AnOversizedReceiptKeepsItsWaivedItems(t *testing.T) {
	r := DecisionReceipt{Iss: "test", Jti: "j"}
	r.Pap.Checklist = append(r.Pap.Checklist, pipeline.Item{Step: 8, Check: "requirements", Status: pipeline.StatusRequired, Code: "HOLD", Decisive: true})
	filler := strings.Repeat("x", 300)
	for range 400 {
		r.Pap.Checklist = append(r.Pap.Checklist, pipeline.Item{Step: 6, Check: "facts", Status: pipeline.StatusMissing, Code: "FACT_MISSING", Detail: filler})
	}
	const exception = "01920000-0000-7000-8000-0000000000e1"
	r.Pap.Checklist = append(r.Pap.Checklist, pipeline.Item{
		Step: 7, Check: "boundaries", Status: pipeline.StatusWaived, Code: "EXCEPTION_APPLIED", Detail: exception,
		Level: "policy org-policy@1 rule no-over-20",
	})
	b, err := fit(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"omitted"`) || !strings.Contains(string(b), exception) || !strings.Contains(string(b), "EXCEPTION_APPLIED") {
		t.Fatalf("the trimmed receipt lost the waived item (%d bytes)", len(b))
	}
}
