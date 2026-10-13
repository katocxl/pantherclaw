// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import "testing"

// TestHR073_RestSegmentsMatchOnlyCleanPaths: a template's last {name*}
// takes one or more segments, each held to the same byte-for-byte rules
// as a single segment, so no encoding, dot or empty segment gets through.
func TestHR073_RestSegmentsMatchOnlyCleanPaths(t *testing.T) {
	tmpl := parseTemplate("/repos/{owner}/{repo}/contents/{path*}")
	vars, ok := matchPath(tmpl, "/repos/acme/payments/contents/src/parser/main.go")
	if !ok || vars["path"] != "src/parser/main.go" || vars["owner"] != "acme" {
		t.Fatalf("nested: %v %v", vars, ok)
	}
	if vars, ok := matchPath(tmpl, "/repos/acme/payments/contents/README.md"); !ok || vars["path"] != "README.md" {
		t.Fatalf("one segment: %v %v", vars, ok)
	}
	for _, raw := range []string{
		"/repos/acme/payments/contents",
		"/repos/acme/payments/contents/",
		"/repos/acme/payments/contents/src//main.go",
		"/repos/acme/payments/contents/src/../.github/x",
		"/repos/acme/payments/contents/./x",
		"/repos/acme/payments/contents/src%2Fmain.go",
		"/repos/acme/payments/other/x",
	} {
		if vars, ok := matchPath(tmpl, raw); ok {
			t.Errorf("%s matched: %v", raw, vars)
		}
	}
}
