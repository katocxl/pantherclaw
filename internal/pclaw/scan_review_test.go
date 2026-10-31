// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// TestD248_AWindowsTaskCarriesItsSettingsAsFlags: a task has no environment,
// so the server, key file and config directory are flags, and a key never is.
// Covers: F888
func TestD248_AWindowsTaskCarriesItsSettingsAsFlags(t *testing.T) {
	s := scanSchedule{goos: "windows", exe: `C:\Program Files\pclaw.exe`, every: 24 * time.Hour, allUsers: true, env: map[string]string{
		"PANTHERCLAW_SERVER": "https://pc.example.com", "PANTHERCLAW_API_KEY_FILE": `C:\keys\scan key`, "PANTHERCLAW_CONFIG_DIR": `C:\pc`,
	}}
	spec, err := s.spec()
	if err != nil {
		t.Fatal(err)
	}
	cmd := strings.Join(spec.install[0], " ")
	for _, want := range []string{`--server "https://pc.example.com"`, `--key-file "C:\keys\scan key"`, `--config-dir "C:\pc"`} {
		if !strings.Contains(cmd, want) {
			t.Errorf("%q lacks %q", cmd, want)
		}
	}
	if strings.Contains(cmd, "--api-key") {
		t.Errorf("a key in the task: %q", cmd)
	}
	s.env["PANTHERCLAW_SERVER"] = `https://x" /RU "attacker`
	if _, err := s.spec(); err == nil {
		t.Error("a quotation mark reached the task's command")
	}
	s.env["PANTHERCLAW_SERVER"] = "https://" + strings.Repeat("a", maxTaskCommand)
	if _, err := s.spec(); err == nil {
		t.Error("a command over the limit of /TR")
	}
}

// TestD248_ScanFlagsAreTheEnvironmentsSettings: the flags a task passes are
// read like the variables, so a scan under a task reaches the same server.
// Covers: F888
func TestD248_ScanFlagsAreTheEnvironmentsSettings(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{".mcp.json": `{"mcpServers": {"s": {"command": "python"}}}`})
	rec, _, env := scanServer(t)
	server, _ := env("PANTHERCLAW_SERVER")
	key, _ := env("PANTHERCLAW_API_KEY")
	keyFile := filepath.Join(dir, "scan.key")
	writeTree(t, dir, map[string]string{"scan.key": key + "\n"})
	bare := func(name string) (string, bool) {
		if name == "HOME" || name == "USERPROFILE" {
			return env(name)
		}
		return "", false
	}
	code, out, errs := run(t, bare, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit",
		"--server", server, "--key-file", keyFile, "--config-dir", dir)
	if code != 0 || rec.req == nil {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
}

func saltDirs(t *testing.T, dir string) {
	t.Helper()
	oldDir, oldID := machineSaltDir, machineID
	t.Cleanup(func() { machineSaltDir, machineID = oldDir, oldID })
	machineSaltDir = func() string { return dir }
	machineID = func() (string, error) { return "machine-1234", nil }
}

func configDir(dir string) Env {
	return func(k string) (string, bool) {
		if k == "PANTHERCLAW_CONFIG_DIR" {
			return dir, true
		}
		return "", false
	}
}

// TestD251_SystemAndAUserGetOneDeviceID: two accounts with their own config
// directories agree through the machine-wide salt; with none, each keeps its
// own.
// Covers: F885
func TestD251_SystemAndAUserGetOneDeviceID(t *testing.T) {
	saltDirs(t, t.TempDir())
	system, err := deviceScope(configDir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	user, err := deviceScope(configDir(t.TempDir()))
	if err != nil || user != system {
		t.Fatalf("SYSTEM %q, user %q, %v", system, user, err)
	}
	// A machine directory nobody may write to falls back to the account's.
	blocked := filepath.Join(t.TempDir(), "file")
	writeTree(t, filepath.Dir(blocked), map[string]string{"file": "x"})
	saltDirs(t, filepath.Join(blocked, "PantherClaw"))
	if _, err := deviceScope(configDir(t.TempDir())); err != nil {
		t.Fatalf("no fallback: %v", err)
	}
}

// TestD250_NoMachineOrPersonLeaves: a device scan sends no hostname unless
// asked, and no home directory in any attribute.
// Covers: F885
func TestD250_NoMachineOrPersonLeaves(t *testing.T) {
	saltDirs(t, t.TempDir())
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{".mcp.json": `{"mcpServers": {"s": {"command": "python"}}}`})
	rec, _, env := scanServer(t)
	if code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit", "--device"); code != 0 {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	if rec.req.GetHost() != "" {
		t.Errorf("hostname sent: %q", rec.req.GetHost())
	}
	if code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit", "--device", "--include-hostname"); code != 0 {
		t.Fatalf("scan = %d %q %q", code, out, errs)
	}
	if rec.req.GetHost() == "" {
		t.Error("--include-hostname sent no hostname")
	}
	if code, _, _ := run(t, env, "scan", "--path", dir, "--submit", "--include-hostname"); code == 0 {
		t.Error("--include-hostname without --device")
	}
	got, ok := submission(scan.Finding{Kind: scan.KindSkill, Attributes: map[string]string{
		"name": "review", "path": `C:\Users\Jo Smith\.claude\skills\review`, "host": "jo-laptop",
	}}, nil)
	if !ok || got.GetAttributes()["path"] != `~\.claude\skills\review` || got.GetAttributes()["host"] != "" {
		t.Fatalf("submission: %v, %v", got, ok)
	}
}

func TestTildeHome(t *testing.T) {
	homes := []string{"/data/alice", `C:\Profiles\bob`}
	for in, want := range map[string]string{
		"/home/alice/.mcp.json":             "~/.mcp.json",
		"/Users/alice/Library/x":            "~/Library/x",
		"/home/alice":                       "~",
		"/data/alice/.claude/settings.json": "~/.claude/settings.json",
		"/data/alicia/x":                    "/data/alicia/x",
		`c:\profiles\BOB\x`:                 `~\x`,
		`D:/Users/carol/x`:                  `~/x`,
		"config=/home/dan/x":                "config=~/x",
		"/opt/home/x/y":                     "/opt/home/x/y",
		"python":                            "python",
	} {
		if got := tildeHome(in, homes); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}

// TestD249_AllUsersRefusesAReplaceableBinary (HR-589's fleet path): as root or
// SYSTEM, a binary a person could replace is refused, by scan and by install.
// Covers: F886
func TestD249_AllUsersRefusesAReplaceableBinary(t *testing.T) {
	oldP, oldB := privileged, binaryProtected
	t.Cleanup(func() { privileged, binaryProtected = oldP, oldB })
	privileged = func() bool { return true }
	binaryProtected = func() bool { return false }
	env := func(string) (string, bool) { return "", false }
	for _, args := range [][]string{{"scan", "--all-users"}, {"scan", "schedule", "install", "--all-users"}} {
		code, _, errs := run(t, env, args...)
		if code == 0 || !strings.Contains(errs, "SCAN_BINARY_WRITABLE") {
			t.Errorf("%v = %d %q", args, code, errs)
		}
	}
}

// Covers: F886
func TestD249_WhoCanReplaceTheBinary(t *testing.T) {
	type node struct {
		uid  uint32
		mode fs.FileMode
	}
	safe := map[string]node{"/": {0, 0o755}, "/usr": {0, 0o755}, "/usr/bin": {0, 0o755}, "/usr/bin/pclaw": {0, 0o755}}
	stat := func(tree map[string]node) func(string) (uint32, fs.FileMode, error) {
		return func(p string) (uint32, fs.FileMode, error) {
			n, ok := tree[p]
			if !ok {
				return 0, 0, errors.New("no such path")
			}
			return n.uid, n.mode, nil
		}
	}
	with := func(p string, n node) map[string]node {
		out := map[string]node{}
		for k, v := range safe {
			out[k] = v
		}
		out[p] = n
		return out
	}
	if !unixBinaryProtected("/usr/bin/pclaw", stat(safe)) {
		t.Error("a root-owned path refused")
	}
	for name, tree := range map[string]map[string]node{
		"a user's binary":      with("/usr/bin/pclaw", node{1000, 0o755}),
		"group write":          with("/usr/bin/pclaw", node{0, 0o775}),
		"world write":          with("/usr/bin/pclaw", node{0, 0o757}),
		"a user's directory":   with("/usr/bin", node{1000, 0o755}),
		"group write above":    with("/usr", node{0, 0o775}),
		"a world-writable top": with("/", node{0, 0o777}),
	} {
		if unixBinaryProtected("/usr/bin/pclaw", stat(tree)) {
			t.Errorf("%s passed", name)
		}
	}
	if unixBinaryProtected("pclaw", stat(safe)) {
		t.Error("a relative path passed")
	}
	pf, sr := `C:\Program Files`, `C:\Windows`
	for exe, want := range map[string]bool{
		`C:\Program Files\PantherClaw\pclaw.exe`: true,
		`c:\windows\system32\pclaw.exe`:          true,
		`C:\Program Files Extra\pclaw.exe`:       false,
		`C:\Users\jo\pclaw.exe`:                  false,
		`C:\Program Files\..\Users\pclaw.exe`:    false,
	} {
		if got := windowsBinaryProtected(exe, pf, sr); got != want {
			t.Errorf("%s = %v", exe, got)
		}
	}
	if windowsBinaryProtected(`C:\x\pclaw.exe`, "", "") {
		t.Error("an empty root passed")
	}
}
