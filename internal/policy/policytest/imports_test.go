// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package policytest_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const importPath = "github.com/katocxl/pantherclaw/internal/policy/policytest"

// TestHR230_ProductCodeNeverImportsPolicytest (G0 M11.1 D10, D29):
// policytest publishes without running the gate, so only tests may use it.
// No non-test Go file in the repository imports it.
func TestHR230_ProductCodeNeverImportsPolicytest(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == importPath {
				t.Errorf("%s imports policytest, which bypasses the publish gate (test setup only)", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("checked only %d files: the walk did not reach the repository", checked)
	}
}
