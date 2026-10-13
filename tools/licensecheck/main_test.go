// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"os"
	"path/filepath"
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
