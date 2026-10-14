// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package receipt_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/receipt"
)

func jws(t *testing.T, claims map[string]any) string {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

func TestPartsMapThePAPClaims(t *testing.T) {
	full := jws(t, map[string]any{"pap": map[string]any{
		"simulated": true,
		"basis":     map[string]any{"policy": "pv-3", "definition": "sha256:abc", "facts": "sha256:def", "levels": []any{map[string]any{"id": "l1"}}},
	}})
	if got := receipt.Missing(full, receipt.Fields); len(got) != 0 {
		t.Errorf("a full receipt lacks %v", got)
	}
	bare := jws(t, map[string]any{"pap": map[string]any{"simulated": false, "basis": map[string]any{"policy": "none", "levels": []any{}}}})
	want := []string{"grant", "policy_version", "package_version", "facts", "simulated"}
	if got := receipt.Missing(bare, receipt.Fields); !slices.Equal(got, want) {
		t.Errorf("a bare receipt lacks %v, want %v", got, want)
	}
	for _, bad := range []string{"", "not-a-jws", "a.!!!.c", "e30.e30.sig"} {
		if got := receipt.Missing(bad, []string{"simulated"}); len(got) != 1 {
			t.Errorf("%q read as carrying evidence", bad)
		}
	}
}
