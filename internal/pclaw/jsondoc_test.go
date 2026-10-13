// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHR208_ConfigEditsKeepWhatTheyDoNotChange: a document laid out as
// Claude Code writes settings comes back byte for byte, members in their
// order; an added member is the only change, in the file's own line
// endings; and what is not one strict JSON object is refused.
func TestHR208_ConfigEditsKeepWhatTheyDoNotChange(t *testing.T) {
	const in = "{\n  \"zeta\": {\n    \"deny\": [\n      \"Bash(curl:*)\"\n    ],\n    \"allow\": []\n  },\n  \"alpha\": 10,\n  \"b\": true\n}"
	doc, err := parseJSONDoc([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := doc.encode()
	if err != nil || string(likeOriginal([]byte(in), out)) != in {
		t.Fatalf("round trip %q %v", out, err)
	}
	if !doc.get("b").bool() || doc.get("zeta").get("deny").itemsOf()[0].str() != "Bash(curl:*)" || doc.get("nope") != nil {
		t.Fatal("reads")
	}
	doc.set("added", jsonFields("z", "last", "a", 1))
	out, _ = doc.encode()
	crlf := strings.ReplaceAll(in, "\n", "\r\n") + "\r\n"
	got := string(likeOriginal([]byte(crlf), out))
	if !strings.HasPrefix(got, strings.TrimSuffix(strings.TrimSuffix(crlf, "}\r\n"), "\r\n")) ||
		!strings.HasSuffix(got, ",\r\n  \"added\": {\r\n    \"z\": \"last\",\r\n    \"a\": 1\r\n  }\r\n}\r\n") {
		t.Fatalf("an added member in CRLF: %q", got)
	}
	for name, bad := range map[string]string{
		"duplicate names": `{"a": 1, "a": 2}`, "an array": `[1]`, "two values": `{} {}`, "truncated": `{"a": `,
		"invalid UTF-8": "{\"a\": \"\xff\"}",
	} {
		if _, err := parseJSONDoc([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if empty, err := parseJSONDoc([]byte("  \n")); err != nil || empty.kind != '{' {
		t.Errorf("an empty file is an empty object: %v", err)
	}
	if hooks, ok := doc.object("alpha"); ok || hooks == nil {
		t.Error("a number member is not an object")
	}
	if _, ok := doc.array("b"); ok {
		t.Error("a boolean member is not an array")
	}
	list, ok := doc.array("new")
	if list.items = append(list.items, jsonOf("x")); !ok || len(doc.get("new").itemsOf()) != 1 {
		t.Error("a missing array member is added")
	}
}

// TestHR208_DiffShowsOneHunkOfWhatChanged: the diff leaves out the lines
// both texts share at the start and end, and is empty for no change.
func TestHR208_DiffShowsOneHunkOfWhatChanged(t *testing.T) {
	before, after := "a\nb\nc\n", "a\nb\nx\ny\nc\n"
	want := "--- f\n+++ f\n@@ line 3 @@\n+x\n+y\n"
	if got := lineDiff("f", []byte(before), []byte(after)); got != want {
		t.Fatalf("diff %q, want %q", got, want)
	}
	if got := lineDiff("f", []byte(before), []byte(before)); got != "" {
		t.Fatalf("no change: %q", got)
	}
	if got := lineDiff("f", nil, []byte("{}\n")); !strings.Contains(got, "+{}") || strings.Contains(got, "\n-") {
		t.Fatalf("a new file: %q", got)
	}
}

// TestHR208_DiffHidesEnvAndHeaderValues: the diff shows each string under
// an env or headers member, in any layout and at any depth, as
// "<redacted>" beside its name, so a token in configuration never reaches
// a terminal, a dry run's output or a CI log; everything else is shown
// byte for byte.
func TestHR208_DiffHidesEnvAndHeaderValues(t *testing.T) {
	token := "ghp_" + strings.Repeat("0123456789ab", 3) // built at run time: no token-like literal in the source
	before := `{"env": {"GITHUB_TOKEN": "` + token + `"}, "mcpServers": {"api": {"type": "http", "url": "https://api.example.test/mcp",
  "headers": {"Authorization" :  "Bearer \u0041` + token + `"}, "args": ["--env", "x"]}}}`
	want := strings.Replace(strings.Replace(before, `"`+token+`"`, `"<redacted>"`, 1), `"Bearer \u0041`+token+`"`, `"<redacted>"`, 1)
	if got := string(redactSecrets([]byte(before))); got != want {
		t.Fatalf("redacted\n%s\nwant\n%s", got, want)
	}
	after := "{\n  \"env\": {\n    \"GITHUB_TOKEN\": \"" + token + "\",\n    \"N\": 1\n  },\n  \"model\": \"opus\"\n}\n"
	got := lineDiff("settings.json", []byte(before), []byte(after))
	for _, shown := range []string{
		`-{"env": {"GITHUB_TOKEN": "<redacted>"}`, `"Authorization" :  "<redacted>"`, `"args": ["--env", "x"]`,
		`+    "GITHUB_TOKEN": "<redacted>",`, `+    "N": 1`, `+  "model": "opus"`,
	} {
		if !strings.Contains(got, shown) {
			t.Errorf("the diff does not show %s:\n%s", shown, got)
		}
	}
	if strings.Contains(got, token[4:]) {
		t.Fatalf("the diff shows the token:\n%s", got)
	}
}

// TestHR208_BackupsAreNeverOverwrittenAndWritesAreWhole: a backup holds
// the original and never replaces an earlier one, even within the same
// second; a file that does not
// exist needs none; a write replaces the whole file through a temporary
// one and leaves nothing behind.
func TestHR208_BackupsAreNeverOverwrittenAndWritesAreWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if name, err := backupFile(path, time.Now()); err != nil || name != "" {
		t.Fatalf("no file: %q %v", name, err)
	}
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC)
	name, err := backupFile(path, at)
	if saved, _ := os.ReadFile(name); err != nil || string(saved) != "original" || !strings.HasSuffix(name, ".pclaw-backup-20261011T090000Z") {
		t.Fatalf("backup %q %q %v", name, saved, err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := backupFile(path, at)
	if saved, _ := os.ReadFile(second); err != nil || second != name+"-2" || string(saved) != "changed" {
		t.Fatalf("a second backup in the same second: %q %q %v", second, saved, err)
	}
	if saved, _ := os.ReadFile(name); string(saved) != "original" {
		t.Fatalf("the first backup changed: %q", saved)
	}
	nested := filepath.Join(dir, "new", ".claude", "settings.local.json")
	if err := writeAtomically(nested, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomically(path, []byte("whole")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "whole" {
		t.Fatalf("written %q", b)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".settings.json.pclaw-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

// TestHR208_ALinkedFileIsChangedWhereItIs: a settings file that is a link
// (kept with the person's dotfiles, say) is backed up and replaced beside
// the file it points to, and the link stays a link; a link to nothing is
// refused and left as it is.
func TestHR208_ALinkedFileIsChangedWhereItIs(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "settings.json")
	link := filepath.Join(dir, "claude", "settings.json")
	for _, d := range []string{filepath.Dir(target), filepath.Dir(link)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("links cannot be made here: %v", err)
	}
	backup, err := backupFile(link, time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	inDotfiles, _ := os.Stat(filepath.Dir(target))
	if beside, _ := os.Stat(filepath.Dir(backup)); beside == nil || !os.SameFile(beside, inDotfiles) {
		t.Fatalf("the backup %s is not beside the linked file", backup)
	}
	if saved, _ := os.ReadFile(backup); string(saved) != "original" {
		t.Fatalf("backup %q", saved)
	}
	if err := writeAtomically(link, []byte("changed")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link was replaced: %v %v", info, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "changed" {
		t.Fatalf("the linked file holds %q", b)
	}
	if beside, _ := os.ReadDir(filepath.Dir(link)); len(beside) != 1 {
		t.Fatalf("files were left beside the link: %v", beside)
	}
	dangling := filepath.Join(dir, "claude", "dangling.json")
	if err := os.Symlink(filepath.Join(dir, "nowhere.json"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomically(dangling, []byte("{}")); err == nil {
		t.Fatal("a link to nothing was written")
	}
	if info, err := os.Lstat(dangling); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link to nothing was replaced: %v %v", info, err)
	}
}
