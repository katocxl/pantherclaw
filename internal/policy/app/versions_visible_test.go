// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR034_NewBundlesRefuseInvisibleText (G0 M11.1 D29): a submitted
// bundle whose rule summary or test summary hides a bidi override or
// another format character is refused with POLICY_INVALID, so it never
// reaches the change-request page people confirm; stored bundles are not
// checked again.
func TestHR034_NewBundlesRefuseInvisibleText(t *testing.T) {
	const ok = `{"id":"p","rules":[{"id":"r","kind":"FORBID","summary":"SUMMARY","operations":["payments.refund.create"],` +
		`"when":"true","reason":"NOPE_NOPE"}],"tests":[{"id":"t","summary":"TEST","action":{"operation":"payments.refund.create","params":{}},` +
		`"expect":{"decision":"DENY","reason":"NOPE_NOPE"}}]}`
	bundle := func(summary, test string) []byte {
		return []byte(strings.NewReplacer("SUMMARY", summary, "TEST", test).Replace(ok))
	}
	if _, err := DecodeBundle(bundle("no refunds", "a refund")); err != nil {
		t.Fatalf("a plain bundle: %v", err)
	}
	for name, raw := range map[string][]byte{
		"a bidi override in a rule summary":     bundle("no refunds "+string(rune(0x202e))+"over 50", "a refund"),
		"an isolate in a rule summary":          bundle("no "+string(rune(0x2066))+"refunds"+string(rune(0x2069))+"", "a refund"),
		"a zero-width joiner in a test summary": bundle("no refunds", "a re"+string(rune(0x200d))+"fund"),
		"a byte-order mark in a rule summary":   bundle(""+string(rune(0xfeff))+"no refunds", "a refund"),
		"a soft hyphen (Cf) in a test summary":  bundle("no refunds", "a re"+string(rune(0x00ad))+"fund"),
	} {
		if _, err := DecodeBundle(raw); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "POLICY_INVALID") {
			t.Errorf("%s: %v", name, err)
		}
	}
	stored := strings.Replace(string(bundle("no refunds "+string(rune(0x202e))+"over 50", "a refund")), `"id":"p"`, `"id":"p","version":1`, 1)
	b, err := decodeStored([]byte(stored))
	if err != nil || b == nil {
		t.Fatalf("a stored bundle no longer decodes: %v", err)
	}
}
