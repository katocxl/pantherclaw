// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// listerPurposes finds every lister purpose the Go code names: constants
// and variables of type (db.)ListerPurpose and db.ListerPurpose("…")
// conversions, in every non-test file under internal/ and cmd/.
func listerPurposes(t *testing.T) []string {
	t.Helper()
	isPurpose := func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name == "ListerPurpose"
		case *ast.SelectorExpr:
			return x.Sel.Name == "ListerPurpose"
		}
		return false
	}
	lit := func(e ast.Expr) (string, bool) {
		b, ok := e.(*ast.BasicLit)
		if !ok || b.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(b.Value)
		return s, err == nil
	}
	seen := map[string]bool{}
	for _, root := range []string{"../internal", "../cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "gen" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					if x.Type != nil && isPurpose(x.Type) {
						for _, v := range x.Values {
							if s, ok := lit(v); ok {
								seen[s] = true
							}
						}
					}
				case *ast.CallExpr:
					if isPurpose(x.Fun) && len(x.Args) == 1 {
						if s, ok := lit(x.Args[0]); ok {
							seen[s] = true
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
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// TestCrossOrgListAcceptsEveryPurpose (G0 M19 E6, HR-053, HR-054): after
// every migration, the audited lister accepts every purpose the Go code
// names, so that a later redefinition of pc.cross_org_list that drops one
// fails here instead of in a background job.
func TestCrossOrgListAcceptsEveryPurpose(t *testing.T) {
	purposes := listerPurposes(t)
	for _, want := range []string{"orgs", "hosting_due", "hosting_assigned", "permits_sweep"} {
		if !slices.Contains(purposes, want) {
			t.Fatalf("the source scan missed %q: %v", want, purposes)
		}
	}
	d := dbtest.New(t)
	p := d.AppPool(t)
	for _, purpose := range purposes {
		err := p.InGlobalTx(context.Background(), db.GlobalCrossOrgList, func(ctx context.Context, tx db.GlobalTx) error {
			_, err := db.CrossOrgListIn(ctx, tx, db.ListerPurpose(purpose), 1, db.ListerParams{})
			return err
		})
		if err != nil {
			t.Errorf("purpose %q: %v", purpose, err)
		}
	}
}
