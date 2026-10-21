// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package config

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestStageSecrets_CopiesRegularFiles0400: every regular file is copied,
// written 0400 so ReadSecretFile accepts it, and a second run replaces the
// earlier copies.
func TestStageSecrets_CopiesRegularFiles0400(t *testing.T) {
	from, to := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"app-password": "pw\n", "kek": "a2Vr"} {
		if err := os.WriteFile(filepath.Join(from, name), []byte(body), 0o644); err != nil { //nolint:gosec // G306: a group-readable source, as a Secret volume shows it
			t.Fatal(err)
		}
	}
	names, err := StageSecrets(from, to)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"app-password", "kek"}) {
		t.Fatalf("staged %v", names)
	}
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(to, n))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o400 {
			t.Errorf("%s mode %v, want 0400", n, fi.Mode().Perm())
		}
		if _, err := ReadSecretFile(filepath.Join(to, n)); err != nil {
			t.Errorf("ReadSecretFile refuses the staged %s: %v", n, err)
		}
	}
	// Again, with a changed value: replaced.
	if err := os.WriteFile(filepath.Join(from, "kek"), []byte("bmV3"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageSecrets(from, to); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(to, "kek")); string(b) != "bmV3" {
		t.Errorf("kek after the second run = %q", b)
	}
	if es, _ := os.ReadDir(to); len(es) != 2 {
		t.Errorf("leftovers in %s: %v", to, es)
	}
}

// TestStageSecrets_RefusesAnythingButRegularFiles: a symbolic link, a
// directory, an oversized file, an empty source or a missing target fails
// the whole command, and nothing is written.
func TestStageSecrets_RefusesAnythingButRegularFiles(t *testing.T) {
	setup := map[string]func(t *testing.T, from string){
		"directory": func(t *testing.T, from string) {
			if err := os.Mkdir(filepath.Join(from, "..data"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"too large": func(t *testing.T, from string) {
			if err := os.WriteFile(filepath.Join(from, "big"), bytes.Repeat([]byte("x"), MaxStagedBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	if runtime.GOOS != "windows" {
		setup["symlink"] = func(t *testing.T, from string) {
			target := filepath.Join(t.TempDir(), "elsewhere")
			if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(from, "kek")); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, mk := range setup {
		t.Run(name, func(t *testing.T) {
			from, to := t.TempDir(), t.TempDir()
			if err := os.WriteFile(filepath.Join(from, "app-password"), []byte("pw"), 0o600); err != nil {
				t.Fatal(err)
			}
			mk(t, from)
			if _, err := StageSecrets(from, to); err == nil {
				t.Fatal("staged")
			}
			if es, _ := os.ReadDir(to); len(es) != 0 {
				t.Errorf("wrote %v before refusing", es)
			}
		})
	}
	if _, err := StageSecrets(t.TempDir(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "no files") {
		t.Errorf("empty source: %v", err)
	}
	if _, err := StageSecrets(t.TempDir(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing target accepted")
	}
}

func TestStageSecretsCommand_Usage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"copy"}, {"stage"}, {"stage", "--from", "x"}, {"stage", "--from", "x", "--to", "y", "extra"}} {
		if err := StageSecretsCommand("pantherclaw-server", args, &out, &errb); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%v: %v, want usage", args, err)
		}
	}
	from, to := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(from, "kek"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := StageSecretsCommand("pantherclaw-server", []string{"stage", "--from", from, "--to", to}, &out, &errb); err != nil ||
		!strings.Contains(out.String(), "staged 1 secret files") {
		t.Errorf("stage: %v %s", err, out.String())
	}
}
