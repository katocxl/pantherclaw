// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ciPolicy = `{"id": "refunds", "rules": [{
  "id": "cap", "kind": "CONSTRAIN", "summary": "no refund above the cap",
  "operations": ["payments.refund.create"], "when": "true", "reason": "REFUND_OVER_CAP",
  "constraint": {"kind": "amount_max", "param": "amount", "max": "MAXIMUM", "currency": "USD"}}],
 "tests": [
  {"id": "under", "summary": "under", "action": {"operation": "payments.refund.create", "target": {"type": "payments.charge", "id": "ch_1"},
    "params": {"amount": {"value": "10.00", "currency": "USD"}, "reason": "duplicate"}},
   "given": {"facts": {"payments.charge.refundable": {"value": {"bool": true}, "age_seconds": 10}}},
   "expect": {"decision": "ALLOW", "reason": "GRANT_COVERS"}},
  {"id": "over", "summary": "over", "action": {"operation": "payments.refund.create", "target": {"type": "payments.charge", "id": "ch_1"},
    "params": {"amount": {"value": "9999.00", "currency": "USD"}, "reason": "duplicate"}},
   "given": {"facts": {"payments.charge.refundable": {"value": {"bool": true}, "age_seconds": 10}}},
   "expect": {"decision": "DENY", "reason": "REFUND_OVER_CAP", "rule": "cap"}}]}`

func ciFile(t *testing.T, cap string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(ciPolicy, "MAXIMUM", cap)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ciRun runs pclaw with no server configured: a check needs none.
func ciRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"ci", "check"}, args...), &out, &errb, func(string) (string, bool) { return "", false }, Options{})
	return code, out.String(), errb.String()
}

// TestD121_CICheckExitCodes: 0 passed, 1 the check failed, 2 it could not
// run, with no server and no sign-in.
func TestD121_CICheckExitCodes(t *testing.T) {
	base := ciFile(t, "500.00")
	if code, out, stderr := ciRun(t, "--policy", base); code != 0 || !strings.Contains(out, "passed") {
		t.Fatalf("pass: exit %d\n%s\n%s", code, out, stderr)
	}
	wider := ciFile(t, "900.00")
	code, out, _ := ciRun(t, "--policy", wider, "--base", base)
	if code != 1 || !strings.Contains(out, "LOOSER") || !strings.Contains(out, "an empty sample proves nothing") {
		t.Fatalf("widening: exit %d\n%s", code, out)
	}
	tighter := ciFile(t, "100.00")
	if code, _, _ := ciRun(t, "--policy", tighter, "--base", base); code != 0 {
		t.Fatalf("tightening: exit %d", code)
	}
	if code, _, _ := ciRun(t, "--policy", tighter, "--base", base, "--fail-on", "any"); code != 1 {
		t.Fatalf("--fail-on any: exit %d", code)
	}
	for name, args := range map[string][]string{
		"no policy":    {},
		"bad flag":     {"--policy", base, "--nope"},
		"bad format":   {"--policy", base, "--format", "xml"},
		"bad fail-on":  {"--policy", base, "--fail-on", "maybe"},
		"extra":        {"--policy", base, "extra"},
		"missing file": {"--policy", filepath.Join(t.TempDir(), "gone.json")},
		"bad packages": {"--policy", base, "--packages", t.TempDir()},
	} {
		if code, _, _ := ciRun(t, args...); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
}

// TestD121_CICheckFormats: json parses, markdown has headings, both carry
// the sample's limit.
func TestD121_CICheckFormats(t *testing.T) {
	base := ciFile(t, "500.00")
	code, out, _ := ciRun(t, "--policy", ciFile(t, "900.00"), "--base", base, "--format", "json")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		Passed   bool           `json:"passed"`
		Outcomes map[string]any `json:"outcome_samples"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Passed || doc.Outcomes["sampled"] == nil || !strings.Contains(doc.Outcomes["limit"].(string), "proves nothing") {
		t.Fatalf("json: %s", out)
	}
	if _, out, _ := ciRun(t, "--policy", base, "--format", "markdown"); !strings.HasPrefix(out, "### PantherClaw policy check") {
		t.Fatalf("markdown: %s", out)
	}
}
