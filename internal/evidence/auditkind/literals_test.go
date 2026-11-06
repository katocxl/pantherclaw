// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
)

const auditImport = `"github.com/katocxl/pantherclaw/internal/evidence/audit"`

// minSites is the floor of audit write sites the walk must see, so a
// broken walk can't pass by seeing nothing.
const minSites = 400

// allowed are the string literals outside this package that equal an
// audit kind and are not an audit write, keyed "<path>|<value>". Each
// entry says what the string is instead.
var allowed = map[string]string{
	"internal/approvals/app/automationgate.go|approval.invalidated": "a notification type, chosen into typ and passed to tell",
	"internal/approvals/app/automationgate.go|approval.expired":     "a notification type, chosen into typ and passed to tell",
	"internal/datarequests/requests.go|data.deletion_requested":     "a notification type, passed to notice",
	"internal/datarequests/requests.go|data.deletion_canceled":      "a notification type, passed to notice",
	"internal/redteam/domain/steps_ui_m29_model.go|model.call":      "the range step kind model.call (G0 M29 D827), a scenario's step name",
	"internal/reflex/domain/kinds.go|signals.event_received":        "the notification type NotifySignalsReceived",
	"internal/reflex/domain/kinds.go|signals.playbook_changed":      "the notification type NotifyPlaybookChanged",
	"internal/signals/cases.go|signals.playbook_failed":             "the kind of a Reflex failure (reflexdomain.Failure.Kind)",
	"internal/waitlist/app/routing.go|approval.requested":           "a notification type, set on a Message's Type",
}

// TestHR664_AuditKindsAreConstants reads every Go file of the server
// (internal/ and cmd/; tests, generated code and testdata aside) with
// go/parser, without types, and refuses (HR-664, T-286):
//
//   - (a) a Name in an audit.Event composite literal (also an element of a
//     []audit.Event or map[K]audit.Event literal) that is a string literal
//     or contains one;
//   - (b) an argument that is or contains a string literal, passed at the
//     kind parameter of an audit helper. An audit helper is a function or
//     method of the caller's own package with a string parameter named
//     name, event, kind or ev*, and that parameter reaches the Name of an
//     audit.Event literal directly or through another audit helper's kind
//     parameter (a fixpoint per package, read from the package's own
//     declarations);
//   - (c) any string literal outside this package equal to a kind of
//     auditkind.All(). Two uses are exempt by structure, because they are
//     not audit kinds even when they share a kind's text: the message of
//     a log call (an *Context or LogAttrs method), and a notification type
//     (a literal in internal/notifications/domain, the Type of a Message
//     literal, or an argument at a typ or notice parameter of a helper of
//     the caller's own package); notification types are their own
//     vocabulary and may diverge. Anything else is on allowed, with why.
//
// It fails if it saw fewer than minSites audit write sites.
func TestHR664_AuditKindsAreConstants(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	kinds := map[string]bool{}
	for _, k := range auditkind.All() {
		kinds[k] = true
	}
	used := map[string]bool{}
	sites := 0
	for _, files := range packages(t, root) {
		helpers := auditHelpers(files)
		notices := noticeHelpers(files)
		for _, pf := range files {
			rel := filepath.ToSlash(pf.rel)
			alias := importName(pf.f, auditImport, "audit")
			exempt := map[*ast.BasicLit]bool{}
			if strings.HasPrefix(rel, "internal/notifications/domain/") {
				ast.Inspect(pf.f, func(n ast.Node) bool {
					if bl, ok := n.(*ast.BasicLit); ok {
						exempt[bl] = true
					}
					return true
				})
			}
			elided := map[*ast.CompositeLit]bool{}
			ast.Inspect(pf.f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					markElided(x, alias, elided)
					if isMessage(x.Type) {
						for _, e := range x.Elts {
							if kv, ok := e.(*ast.KeyValueExpr); ok && isIdent(kv.Key, "Type") {
								if bl, ok := kv.Value.(*ast.BasicLit); ok {
									exempt[bl] = true
								}
							}
						}
					}
					if !isEvent(x.Type, alias) && !elided[x] {
						return true
					}
					for _, e := range x.Elts {
						kv, ok := e.(*ast.KeyValueExpr)
						if !ok || !isIdent(kv.Key, "Name") {
							continue
						}
						sites++
						if hasLiteral(kv.Value) {
							t.Errorf("%s: an audit.Event Name is a string literal; use an auditkind constant (HR-664)", pf.pos(kv.Value))
						}
					}
				case *ast.CallExpr:
					fn := callee(x, alias)
					for _, p := range helpers[fn] {
						if p >= len(x.Args) {
							continue
						}
						sites++
						if hasLiteral(x.Args[p]) {
							t.Errorf("%s: %s is passed an audit kind as a string literal; use an auditkind constant (HR-664)", pf.pos(x.Args[p]), fn)
						}
					}
					for _, p := range notices[fn] {
						if p < len(x.Args) {
							if bl, ok := x.Args[p].(*ast.BasicLit); ok {
								exempt[bl] = true
							}
						}
					}
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && isLogMethod(sel.Sel.Name) {
						i := 1
						if sel.Sel.Name == "LogAttrs" {
							i = 2
						}
						if i < len(x.Args) {
							if bl, ok := x.Args[i].(*ast.BasicLit); ok {
								exempt[bl] = true
							}
						}
					}
				}
				return true
			})
			ast.Inspect(pf.f, func(n ast.Node) bool {
				if _, ok := n.(*ast.ImportSpec); ok {
					return false
				}
				bl, ok := n.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING || exempt[bl] {
					return true
				}
				v, err := strconv.Unquote(bl.Value)
				if err != nil || !kinds[v] {
					return true
				}
				key := rel + "|" + v
				if _, ok := allowed[key]; ok {
					used[key] = true
					return true
				}
				t.Errorf("%s: %q is an audit kind written as a string; use auditkind.%s (HR-664)", pf.pos(bl), v, constName(v))
				return true
			})
		}
	}
	if sites < minSites {
		t.Errorf("saw %d audit write sites, want at least %d: the walk is broken", sites, minSites)
	}
	for key := range allowed {
		if !used[key] {
			t.Errorf("allowed entry %q matches nothing; remove it", key)
		}
	}
}

type parsedFile struct {
	rel  string
	fset *token.FileSet
	f    *ast.File
}

func (p parsedFile) pos(n ast.Node) string {
	at := p.fset.Position(n.Pos())
	return filepath.ToSlash(p.rel) + ":" + strconv.Itoa(at.Line)
}

// packages reads the server's Go files, grouped by directory.
func packages(t *testing.T, root string) map[string][]parsedFile {
	t.Helper()
	out := map[string][]parsedFile{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "gen", "testdata":
					return filepath.SkipDir
				}
				if filepath.Base(path) == "auditkind" && filepath.Base(filepath.Dir(path)) == "evidence" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			out[filepath.Dir(path)] = append(out[filepath.Dir(path)], parsedFile{rel, fset, f})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no Go packages read")
	}
	return out
}

// stringParams returns the positions of fd's string parameters whose name
// passes keep.
func stringParams(fd *ast.FuncDecl, keep func(string) bool) []int {
	var out []int
	i := 0
	for _, fld := range fd.Type.Params.List {
		isString := isIdent(fld.Type, "string")
		if len(fld.Names) == 0 {
			i++
			continue
		}
		for _, n := range fld.Names {
			if isString && keep(n.Name) {
				out = append(out, i)
			}
			i++
		}
	}
	return out
}

func paramAt(fd *ast.FuncDecl, pos int) string {
	i := 0
	for _, fld := range fd.Type.Params.List {
		if len(fld.Names) == 0 {
			i++
			continue
		}
		for _, n := range fld.Names {
			if i == pos {
				return n.Name
			}
			i++
		}
	}
	return ""
}

// auditHelpers finds a package's audit helpers: function or method name to
// the positions of its kind parameters (rule (b)).
func auditHelpers(files []parsedFile) map[string][]int {
	type cand struct {
		fd    *ast.FuncDecl
		pos   []int
		alias string
	}
	var cands []cand
	for _, pf := range files {
		alias := importName(pf.f, auditImport, "audit")
		for _, d := range pf.f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			pos := stringParams(fd, func(n string) bool {
				return n == "name" || n == "event" || n == "kind" || strings.HasPrefix(n, "ev")
			})
			if len(pos) > 0 {
				cands = append(cands, cand{fd, pos, alias})
			}
		}
	}
	helpers := map[string][]int{}
	for changed := true; changed; {
		changed = false
		for _, c := range cands {
			for _, p := range c.pos {
				if slices.Contains(helpers[c.fd.Name.Name], p) {
					continue
				}
				if reachesName(c.fd.Body, paramAt(c.fd, p), c.alias, helpers) {
					helpers[c.fd.Name.Name] = append(helpers[c.fd.Name.Name], p)
					changed = true
				}
			}
		}
	}
	return helpers
}

// reachesName reports whether the parameter param is the Name of an
// audit.Event literal in body or is passed at an audit helper's kind
// parameter.
func reachesName(body *ast.BlockStmt, param, alias string, helpers map[string][]int) bool {
	found := false
	elided := map[*ast.CompositeLit]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.CompositeLit:
			markElided(x, alias, elided)
			if !isEvent(x.Type, alias) && !elided[x] {
				return true
			}
			for _, e := range x.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok && isIdent(kv.Key, "Name") && isIdent(kv.Value, param) {
					found = true
				}
			}
		case *ast.CallExpr:
			for _, p := range helpers[callee(x, alias)] {
				if p < len(x.Args) && isIdent(x.Args[p], param) {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// noticeHelpers finds a package's functions and methods with a string
// parameter named typ or notice: a notification type (rule (c)).
func noticeHelpers(files []parsedFile) map[string][]int {
	out := map[string][]int{}
	for _, pf := range files {
		for _, d := range pf.f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Type.Params == nil {
				continue
			}
			pos := stringParams(fd, func(n string) bool { return n == "typ" || n == "notice" })
			out[fd.Name.Name] = append(out[fd.Name.Name], pos...)
		}
	}
	return out
}

// callee is the name of the same-package function or method a call
// reaches, or "" for a call into the audit package.
func callee(call *ast.CallExpr, alias string) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if isIdent(f.X, alias) {
			return ""
		}
		return f.Sel.Name
	}
	return ""
}

func isEvent(t ast.Expr, alias string) bool {
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	switch x := t.(type) {
	case *ast.SelectorExpr:
		return isIdent(x.X, alias) && x.Sel.Name == "Event"
	case *ast.Ident:
		return false
	}
	return false
}

// markElided marks the untyped element literals of a []audit.Event or
// map[K]audit.Event literal.
func markElided(x *ast.CompositeLit, alias string, elided map[*ast.CompositeLit]bool) {
	var elt ast.Expr
	switch t := x.Type.(type) {
	case *ast.ArrayType:
		elt = t.Elt
	case *ast.MapType:
		elt = t.Value
	}
	if elt == nil || !isEvent(elt, alias) {
		return
	}
	for _, e := range x.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			e = kv.Value
		}
		if u, ok := e.(*ast.UnaryExpr); ok {
			e = u.X
		}
		if cl, ok := e.(*ast.CompositeLit); ok && cl.Type == nil {
			elided[cl] = true
		}
	}
}

// isMessage reports a notification Message literal's type.
func isMessage(t ast.Expr) bool {
	switch x := t.(type) {
	case *ast.SelectorExpr:
		return x.Sel.Name == "Message"
	case *ast.Ident:
		return x.Name == "Message"
	}
	return false
}

func isLogMethod(name string) bool {
	switch name {
	case "DebugContext", "InfoContext", "WarnContext", "ErrorContext", "LogAttrs":
		return true
	}
	return false
}

func hasLiteral(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			found = true
		}
		return !found
	})
	return found
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func importName(f *ast.File, path, def string) string {
	for _, imp := range f.Imports {
		if imp.Path.Value == path {
			if imp.Name != nil {
				return imp.Name.Name
			}
			return def
		}
	}
	return "\x00" // matches no identifier
}

// constName is the constant a kind's text would have.
func constName(k string) string {
	var b strings.Builder
	for _, part := range strings.FieldsFunc(k, func(r rune) bool { return r == '.' || r == '_' }) {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
