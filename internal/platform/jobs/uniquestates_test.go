// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jobs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// riverRequiredStates are the states River 0.48 requires in every custom
// UniqueOpts.ByState (insert_opts.go requiredV3states); an insert with a
// list lacking one fails ("missing: running").
var riverRequiredStates = []string{"JobStateAvailable", "JobStatePending", "JobStateRunning", "JobStateScheduled"}

// TestUniqueByStateHoldsRiversRequiredStates: every river.UniqueOpts that
// sets ByState, anywhere under the module root (every Go file outside
// vendor, testdata, node_modules and dot directories, tests excepted), sets
// it as a literal list holding the available, pending, running and
// scheduled states, so no job's inserts fail at run time (G0 UI D94).
func TestUniqueByStateHoldsRiversRequiredStates(t *testing.T) {
	fset := token.NewFileSet()
	found := 0
	for _, root := range []string{moduleRoot(t)} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch name := d.Name(); {
				case path == root:
				case name == "vendor", name == "testdata", name == "node_modules", strings.HasPrefix(name, "."):
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isSelector(lit.Type, "river", "UniqueOpts") {
					return true
				}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "ByState" {
						continue
					}
					found++
					at := fset.Position(kv.Pos())
					list, ok := kv.Value.(*ast.CompositeLit)
					if !ok {
						t.Errorf("%s: ByState must be a literal list so it can be checked", at)
						continue
					}
					var states []string
					for _, s := range list.Elts {
						if sel, ok := s.(*ast.SelectorExpr); ok {
							states = append(states, sel.Sel.Name)
						}
					}
					for _, need := range riverRequiredStates {
						if !slices.Contains(states, need) {
							t.Errorf("%s: ByState lacks rivertype.%s, which River requires", at, need)
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found < 30 {
		t.Fatalf("found %d ByState lists; the scan is not reading the product code", found)
	}
}

// moduleRoot is the directory of the nearest go.mod above the test's.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}
