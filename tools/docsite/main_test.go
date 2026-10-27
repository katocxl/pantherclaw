// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderSafeMarkdownAndLinks(t *testing.T) {
	source := []byte("# Guide\n\n<script>alert(1)</script>\n\n[unsafe](javascript:alert%281%29)\n\n[local](../quickstart.md#start) [source](../BUILD_GUIDE.md#scope)\n\n![Diagram](../diagram.svg)\n\n```sh\npclaw-command-only-in-code\n```\n\n| Key | Value |\n| --- | --- |\n| ready | yes |\n")
	item, body, err := render("docs/runbooks/deploy.md", source, map[string]bool{"docs/quickstart.md": true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, forbidden := range []string{"<script>", `href="javascript:`} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("unsafe output: %s", s)
		}
	}
	for _, want := range []string{`href="../quickstart.html#start"`, sourceBase + "docs/BUILD_GUIDE.md#scope", imageBase + "docs/diagram.svg", "<table>", `id="guide"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %s", want, s)
		}
	}
	if item.Title != "Guide" || item.URL != "docs/runbooks/deploy.html" || !strings.Contains(item.Text, "ready") || !strings.Contains(item.Text, "pclaw-command-only-in-code") {
		t.Fatalf("index entry: %+v", item)
	}
}

func TestBuildCuratesAndRefusesExistingOutput(t *testing.T) {
	root := t.TempDir()
	write := func(name, value string) {
		t.Helper()
		name = filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/site.json", `{"sources":["docs/quickstart.md"]}`)
	write("docs/quickstart.md", "# Quickstart\n\nInstall PantherClaw.")
	write("docs/g0/private-notes.md", "NOT PUBLISHED")
	out := filepath.Join(root, "output")
	if err := build(root, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(out, "search.json"))
	if err != nil || strings.Contains(string(b), "NOT PUBLISHED") || !strings.Contains(string(b), "Quickstart") {
		t.Fatalf("curated index: %s, %v", b, err)
	}
	b, err = os.ReadFile(filepath.Join(out, "docs/quickstart.html"))
	if err != nil || !strings.Contains(string(b), `href="../site.css"`) {
		t.Fatalf("relative asset path: %s, %v", b, err)
	}
	if err := build(root, out); err == nil {
		t.Fatal("must not overwrite an existing output directory")
	}
	write("docs/site.json", `{"sources":["../outside"]}`)
	if _, err := selected(root); err == nil {
		t.Fatal("must reject manifest traversal")
	}
}
