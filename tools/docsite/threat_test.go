// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// eventHandler matches an inline event handler attribute such as onclick=.
var eventHandler = regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`)

// TestT180_ShippedSiteHasNoInternalDocsAndNoActiveContent: the shipped
// manifest (docs/site.json) selects no planning brief, security review
// record, tracker or reference specification, and no selected document
// renders a script element, a javascript: link or an inline event handler
// (G0 M13 wave 3; T-180).
func TestT180_ShippedSiteHasNoInternalDocsAndNoActiveContent(t *testing.T) {
	root := filepath.Join("..", "..")
	names, err := selected(root)
	if err != nil {
		t.Fatal(err)
	}
	published := map[string]bool{}
	for _, name := range names {
		published[name] = true
	}
	for _, name := range names {
		for _, internal := range []string{"docs/g0/", "docs/security/", "docs/reference/", ".claude/"} {
			if strings.HasPrefix(name, internal) {
				t.Errorf("the site publishes internal document %s", name)
			}
		}
		source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		_, body, err := render(name, source, published)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s := strings.ToLower(string(body))
		if strings.Contains(s, "<script") || strings.Contains(s, `href="javascript:`) || eventHandler.Match(body) {
			t.Errorf("%s renders active content", name)
		}
	}
}
