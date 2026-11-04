// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import "testing"

// TestHR664_RewrapKinds: each key type re-wrapped today keeps its audit
// kind byte for byte, and an unknown type is refused (HR-664).
func TestHR664_RewrapKinds(t *testing.T) {
	t.Parallel()
	for typ, want := range map[string]string{"dek": "dek.rewrapped", "signing_key": "signing_key.rewrapped"} {
		got, err := rewrappedKind(typ)
		if err != nil || got != want {
			t.Errorf("rewrappedKind(%q) = %q, %v; want %q", typ, got, err, want)
		}
	}
	if got, err := rewrappedKind("webhook_key"); err == nil {
		t.Errorf("rewrappedKind(webhook_key) = %q, want an error", got)
	}
}
