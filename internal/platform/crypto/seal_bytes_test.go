// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"bytes"
	"testing"
)

// TestHR411_ASealKeySerializesTheSameEveryTime: a seal private key's
// Bytes is the same on every call, and clearing what it returned changes
// nothing, on every suite the build allows. The MCP task-id key is derived
// from it on each gateway replica (G0 M15 D16), so it must not drift.
func TestHR411_ASealKeySerializesTheSameEveryTime(t *testing.T) {
	for _, s := range []SealSuite{SuiteXWing, SuiteMLKEM768P256} {
		if _, err := s.kem(); err != nil {
			continue // not allowed in this build (FIPS 140-only has no X-Wing)
		}
		k, err := GenerateSealKeySuite(s)
		if err != nil {
			t.Fatal(err)
		}
		first, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		keep := bytes.Clone(first)
		clear(first)
		second, err := k.Bytes()
		if err != nil || !bytes.Equal(second, keep) {
			t.Fatalf("%v: Bytes changed after the first call was cleared: %v", s, err)
		}
		parsed, err := ParseSealPrivateKey(second)
		if err != nil {
			t.Fatal(err)
		}
		if again, _ := parsed.Bytes(); !bytes.Equal(again, keep) {
			t.Fatalf("%v: a parsed key serializes differently", s)
		}
	}
}
