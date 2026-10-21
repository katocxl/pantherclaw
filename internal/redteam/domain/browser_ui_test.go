// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// TestUI_BrowserCallStep: browser.call takes only its closed fields and
// values, never a host or URL, needs requires: [browser] and an expected
// outcome (G0 UI, RT-060, RT-061).
func TestUI_BrowserCallStep(t *testing.T) {
	ok := header + "requires: [browser]\nsteps:\n" +
		"  - {id: a, do: browser.call, with: {target: api, origin: cross_site, csrf: true, method: POST, body: json}, expect: {outcome: REFUSED}}\n" +
		"  - {id: b, do: browser.call, with: {target: ops_stream, origin: same_origin, csrf: true, bearer: true, method: GET, body: form}, expect: {outcome: ALLOW}}\n"
	if _, err := domain.Parse([]byte(ok)); err != nil {
		t.Fatalf("valid browser.call: %v", err)
	}
	for name, with := range map[string]string{
		"unknown target":  "{target: account, origin: same_origin, method: POST, body: json}",
		"unknown origin":  "{target: api, origin: https://evil.example, method: POST, body: json}",
		"unknown method":  "{target: api, origin: same_origin, method: PUT, body: json}",
		"unknown body":    "{target: api, origin: same_origin, method: POST, body: xml}",
		"a URL":           "{target: api, origin: same_origin, method: POST, body: json, url: http://x}",
		"missing origin":  "{target: api, method: POST, body: json}",
		"a header to set": "{target: api, origin: same_origin, method: POST, body: json, headers: {Origin: x}}",
	} {
		doc := header + "requires: [browser]\nsteps:\n  - {id: a, do: browser.call, with: " + with + ", expect: {outcome: REFUSED}}\n"
		if _, err := domain.Parse([]byte(doc)); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	noCap := header + "steps:\n  - {id: a, do: browser.call, with: {target: api, origin: same_origin, method: POST, body: json}, expect: {outcome: ALLOW}}\n"
	if _, err := domain.Parse([]byte(noCap)); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("without requires browser: %v", err)
	}
	noExpect := header + "requires: [browser]\nsteps:\n  - {id: a, do: browser.call, with: {target: api, origin: same_origin, method: POST, body: json}}\n"
	if _, err := domain.Parse([]byte(noExpect)); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("without an expected outcome: %v", err)
	}
}
