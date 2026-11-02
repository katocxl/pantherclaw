// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package behavior_test

import (
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/katocxl/pantherclaw/"

// decisionPath are the packages that decide an action or an approval, and
// the gateway that enforces it (HR-030, HR-034, HR-240).
var decisionPath = []string{"internal/authority", "internal/approvals", "internal/gateway"}

// TestHR641_TheDecisionPathNeverReachesBehavior: no package of the decision
// path imports internal/behavior, directly or through any other package of
// this module, so no decision can read a profile, a deviation or an
// approval's behaviour context (HR-641, HR-645). Covers: F930, F934
func TestHR641_TheDecisionPathNeverReachesBehavior(t *testing.T) {
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Dir(filepath.Dir(here)) // internal/behavior -> repo root
	if _, err := os.Stat(filepath.Join(repo, "go.mod")); err != nil {
		t.Fatalf("repo root %s: %v", repo, err)
	}
	dirOf := func(pkg string) string {
		return filepath.Join(repo, filepath.FromSlash(strings.TrimPrefix(pkg, module)))
	}
	var roots []string
	for _, top := range decisionPath {
		err := filepath.WalkDir(filepath.Join(repo, filepath.FromSlash(top)), func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			if _, err := build.ImportDir(path, 0); err == nil {
				rel, err := filepath.Rel(repo, path)
				if err != nil {
					return err
				}
				roots = append(roots, module+filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(roots) < 3 {
		t.Fatalf("found %d decision-path packages", len(roots))
	}
	forbidden := module + "internal/behavior"
	seen := map[string]bool{}
	var walk func(pkg, from string)
	walk = func(pkg, from string) {
		if seen[pkg] || !strings.HasPrefix(pkg, module) {
			return
		}
		seen[pkg] = true
		if pkg == forbidden || strings.HasPrefix(pkg, forbidden+"/") {
			t.Errorf("the decision path reaches %s (imported by %s)", pkg, from)
			return
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
	for _, p := range roots {
		walk(p, "")
	}
	if len(seen) < 10 {
		t.Fatalf("walked only %d packages", len(seen))
	}
}
