// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ticketsync_test

import (
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/katocxl/pantherclaw/"

// authorityPackages are the services a ticket must never reach (D255): the
// response service (containment, restoration, the kill switch), approvals
// and the waitlist that decides them, and the authority pipeline with its
// containment and restore stores.
var authorityPackages = []string{
	module + "internal/response",
	module + "internal/approvals",
	module + "internal/waitlist",
	module + "internal/authority",
	module + "internal/restore",
}

// TestHR527_TicketSyncImportsNoAuthority: no package under
// internal/ticketsync imports, directly or through any other package of
// this module, the response, restoration, approvals or kill-switch
// services, so system:ticketsync has no code path that could restore
// authority or lift containment (HR-527, T-227).
//
// Covers: F545
func TestHR527_TicketSyncImportsNoAuthority(t *testing.T) {
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Dir(filepath.Dir(here)) // internal/ticketsync -> repo root
	if _, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil {
		t.Fatalf("repo root %s: %v", repo, err)
	}
	dirOf := func(pkg string) string {
		return filepath.Join(repo, filepath.FromSlash(strings.TrimPrefix(pkg, module)))
	}
	var pkgs []string
	err = filepath.WalkDir(here, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		if _, err := build.ImportDir(path, 0); err == nil {
			rel, err := filepath.Rel(repo, path)
			if err != nil {
				return err
			}
			pkgs = append(pkgs, module+filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil || len(pkgs) < 2 {
		t.Fatalf("found %d ticketsync packages: %v", len(pkgs), err)
	}
	seen := map[string]bool{}
	var walk func(pkg, from string)
	walk = func(pkg, from string) {
		if seen[pkg] || !strings.HasPrefix(pkg, module) {
			return
		}
		seen[pkg] = true
		for _, f := range authorityPackages {
			if pkg == f || strings.HasPrefix(pkg, f+"/") {
				t.Errorf("internal/ticketsync reaches %s (imported by %s)", pkg, from)
				return
			}
		}
		p, err := build.ImportDir(dirOf(pkg), 0)
		if err != nil {
			t.Errorf("import %s: %v", pkg, err)
			return
		}
		for _, imp := range p.Imports {
			walk(imp, pkg)
		}
	}
	for _, p := range pkgs {
		walk(p, "")
	}
	if len(seen) < 10 {
		t.Fatalf("walked only %d packages", len(seen))
	}
}
