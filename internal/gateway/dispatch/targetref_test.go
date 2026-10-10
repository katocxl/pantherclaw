// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"os"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
)

// TestHR190_TheGatewaySendsOnlyTheReference: from an accepted answer the
// gateway reads one identifier at the place the verifier names, printable
// and short, never one carrying the credential; nothing else of the body
// leaves for the Authority (G0 M7 design decision 5).
func TestHR190_TheGatewaySendsOnlyTheReference(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	create, _ := p.Definition("payments.refund.create")
	get, _ := p.Definition("payments.refund.get")
	secret := []byte("sk_test_secret")
	for body, want := range map[string]string{
		`{"id":"re_0192-ab","status":"succeeded"}`:  "re_0192-ab",
		`{"status":"succeeded"}`:                    "",
		`{"id":12}`:                                 "12",
		`{"id":{"nested":"re_1"}}`:                  "",
		`{"id":"re 1"}`:                             "",
		`{"id":"re_sk_test_secret"}`:                "",
		`{"id":"` + strings.Repeat("a", 257) + `"}`: "",
		`{"id":"re_1","id":"re_2"}`:                 "",
		`not json`:                                  "",
	} {
		if got := targetRef(create, []byte(body), secret); got != want {
			t.Errorf("%s: %q, want %q", body, got, want)
		}
	}
	if got := targetRef(get, []byte(`{"id":"re_1"}`), nil); got != "" {
		t.Fatalf("a definition without a verifier reference sent %q", got)
	}
}
