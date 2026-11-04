// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var kindShape = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// TestHR664_KindsPackageIsClosed reads this package's own files: every
// exported constant is named in all exactly once, no two constants share
// a value, and every value is a dotted lowercase kind (HR-664).
func TestHR664_KindsPackageIsClosed(t *testing.T) {
	t.Parallel()
	consts := map[string]string{} // name -> value
	var listed []string
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, s := range g.Specs {
				vs, ok := s.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					switch {
					case g.Tok == token.CONST && n.IsExported():
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							t.Errorf("%s: %s is not a string literal", p, n.Name)
							continue
						}
						v, _ := strconv.Unquote(lit.Value)
						if _, dup := consts[n.Name]; dup {
							t.Errorf("%s declared twice", n.Name)
						}
						consts[n.Name] = v
					case g.Tok == token.VAR && n.Name == "all":
						cl, ok := vs.Values[i].(*ast.CompositeLit)
						if !ok {
							t.Fatalf("all is not a slice literal")
						}
						for _, e := range cl.Elts {
							id, ok := e.(*ast.Ident)
							if !ok {
								t.Errorf("all holds %T, want a constant's name", e)
								continue
							}
							listed = append(listed, id.Name)
						}
					}
				}
			}
		}
	}
	if len(consts) == 0 {
		t.Fatal("no constants read")
	}
	seen := map[string]int{}
	for _, n := range listed {
		seen[n]++
	}
	values := map[string]string{}
	for n, v := range consts {
		if seen[n] != 1 {
			t.Errorf("%s is in all %d times, want once", n, seen[n])
		}
		if o, ok := values[v]; ok {
			t.Errorf("%s and %s share the value %q", o, n, v)
		}
		values[v] = n
		if !kindShape.MatchString(v) {
			t.Errorf("%s = %q is not a dotted lowercase kind", n, v)
		}
	}
	for n := range seen {
		if _, ok := consts[n]; !ok {
			t.Errorf("all names %s, which is not an exported constant", n)
		}
	}
	got := All()
	if len(got) != len(consts) || !slices.IsSorted(got) {
		t.Errorf("All() has %d kinds (sorted %t), want %d sorted", len(got), slices.IsSorted(got), len(consts))
	}
	got[0] = "changed"
	if All()[0] == "changed" {
		t.Error("All() returns the package's own slice")
	}
}
