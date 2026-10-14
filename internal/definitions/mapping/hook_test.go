// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

func shellMapper(t testing.TB) *Mapper {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/pc-shell/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return mapperFor(t, raw)
}

func hookInput(shell, command, cwd, call string) string {
	return fmt.Sprintf(`{"shell":%q,"command":%q,"cwd":%q,"call":%q}`, shell, command, cwd, call)
}

// TestHR124_PcShellMappingGolden pins the ActionIR of the hook mapping:
// the command as sent and the working directory normalized (HR-187).
func TestHR124_PcShellMappingGolden(t *testing.T) {
	m := shellMapper(t)
	var out bytes.Buffer
	for _, in := range []string{
		hookInput("bash", "go test ./...", "/home/dev/repo/./src/..", "toolu_01"),
		hookInput("powershell", "Get-ChildItem -Force\nRemove-Item .\\tmp", `c:/Users/dev/repo/`, "toolu_02"),
		hookInput("bash", "ls", `\\fileserver\share\team\..\repo`, "toolu_03"),
	} {
		p, err := m.Hook(context.Background(), tc, "shell", []byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		fmt.Fprintf(&out, "hook shell %s\n%s\n", p.HashHex(), p.Canonical)
	}
	path := filepath.Join("testdata", "pc-shell.actionir")
	if *update {
		if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("mapping output changed; a mapping change must be deliberate (HR-124).\n got:\n%s\nwant:\n%s", out.Bytes(), want)
	}
}

// TestHR187_TheHookMappingNormalizesOnlyTheDirectory: two spellings of one
// directory are one action, the command text is never changed, and what
// cannot be normalized, or is not plain text, is ambiguous.
func TestHR187_TheHookMappingNormalizesOnlyTheDirectory(t *testing.T) {
	m := shellMapper(t)
	ctx := context.Background()
	a, err := m.Hook(ctx, tc, "shell", []byte(hookInput("powershell", "dir  C:/x", `c:\Users\dev\.\repo`, "toolu_1")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Hook(ctx, tc, "shell", []byte(hookInput("powershell", "dir  C:/x", `C:/Users/dev/repo/`, "toolu_1")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Canonical, b.Canonical) || !strings.Contains(string(a.Action.Params), `"command":"dir  C:/x"`) ||
		!strings.Contains(string(a.Action.Params), `"cwd":"C:\\Users\\dev\\repo"`) || a.Action.Channel != "hook" {
		t.Fatalf("not one action:\n%s\n%s", a.Canonical, b.Canonical)
	}
	if a.Action.DedupeKey == "" {
		t.Fatal("the call id is the dedupe key (HR-007)")
	}
	for name, in := range map[string]string{
		"device path":       hookInput("bash", "ls", `\\?\C:\x`, "toolu_1"),
		"data stream":       hookInput("bash", "ls", `C:\repo\x:hidden`, "toolu_1"),
		"trailing dot":      hookInput("bash", "ls", `C:\repo.`, "toolu_1"),
		"loopback share":    hookInput("powershell", "ls", `\\localhost\C$\repo`, "toolu_1"),
		"admin share":       hookInput("powershell", "ls", `\\dev-pc\c$\repo`, "toolu_1"),
		"relative":          hookInput("bash", "ls", `repo`, "toolu_1"),
		"bidi command":      hookInput("bash", "echo a\u202eb", "/x", "toolu_1"),
		"carriage return":   hookInput("bash", "ls\r\nrm -rf /", "/x", "toolu_1"),
		"zero-width":        hookInput("bash", "rm\u200b -rf /", "/x", "toolu_1"),
		"unknown shell":     hookInput("zsh", "ls", "/x", "toolu_1"),
		"bad call id":       hookInput("bash", "ls", "/x", "toolu 1"),
		"long command":      hookInput("bash", strings.Repeat("a", 8193), "/x", "toolu_1"),
		"extra field":       `{"shell":"bash","command":"ls","cwd":"/x","call":"toolu_1","sudo":true}`,
		"missing directory": `{"shell":"bash","command":"ls","call":"toolu_1"}`,
	} {
		if _, err := m.Hook(ctx, tc, "shell", []byte(in)); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := m.Hook(ctx, tc, "Bash", []byte(hookInput("bash", "ls", "/x", "toolu_1"))); !errors.Is(err, ErrUnmapped) {
		t.Errorf("unknown hook kind: %v", err)
	}
	if _, err := m.MCP(ctx, tc, "shell", []byte(hookInput("bash", "ls", "/x", "toolu_1"))); !errors.Is(err, ErrUnmapped) {
		t.Errorf("a hook mapping answered an MCP call: %v", err)
	}
}
