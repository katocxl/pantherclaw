// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestExpectedLicense(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"internal/platform/version/version.go":                  spdxBUSL,
		"cmd/pclaw/main.go":                                     spdxBUSL,
		"sdk/go/pap/pap.go":                                     spdxApache,
		"sdk/python/pantherclaw/__init__.py":                    spdxApache,
		"integrations/claude-code/hook.ts":                      spdxApache,
		"integrations/claude-agent-sdk/typescript/src/index.ts": spdxApache,
		"docs/protocol/example.go":                              spdxApache,
		"hub/tools/x.sh":                                        spdxApache,
		"sdkx/other.go":                                         spdxBUSL,
	}
	for p, want := range cases {
		if got := ExpectedLicense(p); got != want {
			t.Errorf("ExpectedLicense(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestCheckReportsAndFixes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	write(t, root, "ok.go", "// SPDX-License-Identifier: BUSL-1.1\n// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.\n\npackage ok\n")
	write(t, root, "missing.go", "package missing\n")
	write(t, root, "sdk/go/wrong.go", "// SPDX-License-Identifier: BUSL-1.1\n// Copyright 2026 Joshua Kato\n\npackage wrong\n")
	write(t, root, "script.sh", "#!/bin/sh\necho hi\n")
	write(t, root, "q.sql", "SELECT 1;\n")
	write(t, root, "README.md", "no header needed\n")
	write(t, root, "testdata/fixture.go", "package fixture\n")
	write(t, root, "tools/pins/x/x.go", "package x\n")
	write(t, root, "proto/third_party/otlp/x.proto", "// Copyright The OpenTelemetry Authors\nsyntax = \"proto3\";\n")
	write(t, root, "internal/gen/opentelemetry/x/x.pb.go", "package x\n")

	problems, fixed, err := Check(os.DirFS(root), root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 0 {
		t.Fatalf("check mode must not fix: %v", fixed)
	}
	got := map[string]string{}
	for _, p := range problems {
		got[p.Path] = p.Reason
	}
	for _, want := range []string{"missing.go", "sdk/go/wrong.go", "script.sh", "q.sql"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected a problem for %s, got %v", want, got)
		}
	}
	if len(got) != 4 {
		t.Fatalf("unexpected problems: %v", got)
	}
	if !strings.Contains(got["sdk/go/wrong.go"], "want Apache-2.0") {
		t.Fatalf("wrong-licence reason not reported: %q", got["sdk/go/wrong.go"])
	}

	problems, fixed, err = Check(os.DirFS(root), root, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 3 || len(problems) != 1 || problems[0].Path != "sdk/go/wrong.go" {
		t.Fatalf("fix mode: fixed=%v problems=%v", fixed, problems)
	}
	sh, err := os.ReadFile(filepath.Join(root, "script.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sh, []byte("#!/bin/sh\n# SPDX-License-Identifier: BUSL-1.1\n")) {
		t.Fatalf("shebang must stay first:\n%s", sh)
	}
	sql, err := os.ReadFile(filepath.Join(root, "q.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(sql, []byte("-- SPDX-License-Identifier: BUSL-1.1\n-- Copyright")) {
		t.Fatalf("sql header wrong:\n%s", sql)
	}

	// After fixing, only the wrong-licence file remains.
	problems, _, err = Check(os.DirFS(root), root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 {
		t.Fatalf("after fix: %v", problems)
	}
}

func TestAddHeaderApache(t *testing.T) {
	t.Parallel()

	out := string(AddHeader([]byte("package pap\n"), "//", spdxApache))
	want := "// SPDX-License-Identifier: Apache-2.0\n// Copyright 2026 Joshua Kato\n\npackage pap\n"
	if out != want {
		t.Fatalf("AddHeader() =\n%q\nwant\n%q", out, want)
	}
}

func TestRunExitCodes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	write(t, root, "a.go", "package a\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-root", root}, &stdout, &stderr); code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if code := run([]string{"-root", root, "-fix"}, &stdout, &stderr); code != 0 {
		t.Fatalf("fix code = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if code := run([]string{"-bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("usage code = %d, want 2", code)
	}
}

const noticeHead = "PantherClaw\n\nSeparately Licensed Components\n----\nThe following:\n\n"

// TestCheckListed (G0 M23 D111, D139): every directory NOTICE lists has a
// LICENSE, every integration is listed, and none of them may be absent.
//
// Covers: F848
func TestCheckListed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	write(t, root, "NOTICE", noticeHead+
		"  sdk/go/   Go SDK\n  hub/   content\n  integrations/x/ x\n  integrations/github-action/ x\n\nReference documents\n---\n  docs/reference/ not licensed separately\n")
	write(t, root, "sdk/go/LICENSE", "apache")
	write(t, root, "integrations/x/LICENSE", "apache")
	write(t, root, "integrations/github-action/LICENSE", "apache")
	got := CheckListed(os.DirFS(root))
	if len(got) != 1 || got[0].Path != "hub/" || !strings.Contains(got[0].Reason, "no LICENSE") {
		t.Fatalf("a listed directory without a LICENSE: %+v", got)
	}
	write(t, root, "hub/LICENSE", "apache")
	if got := CheckListed(os.DirFS(root)); len(got) != 0 {
		t.Fatalf("every listed directory is licensed: %+v", got)
	}
	if err := os.RemoveAll(filepath.Join(root, "integrations", "github-action")); err != nil {
		t.Fatal(err)
	}
	if got := CheckListed(os.DirFS(root)); len(got) != 1 || got[0].Path != "integrations/github-action/" {
		t.Fatalf("a listed integration that is absent: %+v", got)
	}
	write(t, root, "integrations/github-action/LICENSE", "apache")
	write(t, root, "integrations/y/LICENSE", "apache")
	if got := CheckListed(os.DirFS(root)); len(got) != 1 || got[0].Path != "integrations/y/" || got[0].Reason != "not listed in NOTICE" {
		t.Fatalf("an unlisted integration: %+v", got)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-root", root}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "integrations/y/") {
		t.Fatalf("run = %d, stdout %q", code, stdout.String())
	}
	write(t, root, "NOTICE", noticeHead+"  sdk/go/ x\n  sdk/gone/ x\n  integrations/x/ x\n  integrations/y/ x\n  integrations/github-action/ x\n")
	if got := CheckListed(os.DirFS(root)); len(got) != 1 || got[0].Path != "sdk/gone/" {
		t.Fatalf("a listed directory that does not exist: %+v", got)
	}
}

// TestRepositoryNoticeIsChecked runs the listing check on this repository.
//
// Covers: F848
func TestRepositoryNoticeIsChecked(t *testing.T) {
	t.Parallel()

	repo := os.DirFS(filepath.Join("..", ".."))
	if got := CheckListed(repo); len(got) != 0 {
		t.Fatalf("NOTICE: %+v", got)
	}
	notice, err := os.ReadFile(filepath.Join("..", "..", "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	dirs := ListedDirs(notice)
	for _, want := range []string{
		"hub/", "integrations/crewai/", "integrations/langchain/", "integrations/mcp/", "integrations/openai-agents/", "integrations/vercel-ai/",
		"integrations/github-action/", "integrations/gitlab/", "integrations/siem/",
	} {
		if !slices.Contains(dirs, want) {
			t.Errorf("NOTICE does not list %s: %v", want, dirs)
		}
	}
	if slices.Contains(dirs, "docs/reference/") {
		t.Errorf("the reference documents are not separately licensed: %v", dirs)
	}
}
