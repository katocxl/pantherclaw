// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// repoRoot finds the module root from this package's directory.
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
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}

// keyConstants are the Key* constants of this package by name.
func keyConstants(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "attrs.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok {
			for i, name := range vs.Names {
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && strings.HasPrefix(name.Name, "Key") {
					v, _ := strconv.Unquote(lit.Value)
					out[name.Name] = v
				}
			}
		}
		return true
	})
	return out
}

// attributeConstructors are the otel attribute functions whose first
// argument is a key.
var attributeConstructors = map[string]bool{
	"String": true, "StringSlice": true, "Int": true, "IntSlice": true, "Int64": true, "Int64Slice": true,
	"Float64": true, "Float64Slice": true, "Bool": true, "BoolSlice": true, "Stringer": true, "Key": true,
}

// TestHR380_EveryAttributeKeyIsAllowListed walks every Go file of the
// server (internal/ and cmd/, tests and generated code aside) and checks
// each OpenTelemetry attribute it builds: the key must be a string literal
// or one of this package's Key constants, and on the allow-list (G0 M13
// D30). A key computed at run time fails the test, so nothing can slip a
// payload, secret, email, token or SQL argument in as a key.
func TestHR380_EveryAttributeKeyIsAllowListed(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	consts := keyConstants(t)
	for name, v := range consts {
		if !Allowed(v) {
			t.Errorf("constant %s = %q is not on the allow-list", name, v)
		}
	}
	seen := 0
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
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
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			alias := ""
			for _, imp := range f.Imports {
				if imp.Path.Value == `"go.opentelemetry.io/otel/attribute"` {
					alias = "attribute"
					if imp.Name != nil {
						alias = imp.Name.Name
					}
				}
			}
			if alias == "" {
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != alias || !attributeConstructors[sel.Sel.Name] {
					return true
				}
				seen++
				at := fset.Position(call.Pos())
				var key string
				switch a := call.Args[0].(type) {
				case *ast.BasicLit:
					key, _ = strconv.Unquote(a.Value)
				case *ast.SelectorExpr:
					if x, ok := a.X.(*ast.Ident); ok && x.Name == "telemetry" {
						key = consts[a.Sel.Name]
					}
				case *ast.Ident:
					if strings.HasSuffix(filepath.Dir(at.Filename), filepath.Join("platform", "telemetry")) {
						key = consts[a.Name]
					}
				}
				if key == "" {
					t.Errorf("%s: attribute key is not a literal or a telemetry.Key constant", at)
				} else if !Allowed(key) {
					t.Errorf("%s: attribute key %q is not on the allow-list (HR-380)", at, key)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Fatal("found no attribute constructors: the walk is broken")
	}
}

// TestHR380_FilterDropsEverythingElse checks the single filter and that
// the exporters and the /metrics text drop attributes it refuses, however
// they were recorded.
func TestHR380_FilterDropsEverythingElse(t *testing.T) {
	t.Parallel()
	for _, kv := range []attribute.KeyValue{
		attribute.String("email", "a@example.com"), attribute.String("db.statement", "SELECT 1"),
		attribute.String("authorization", "Bearer x"), attribute.String("payload", "{}"),
		attribute.String(KeyCode, strings.Repeat("x", maxValueBytes+1)),
		attribute.StringSlice(KeyCode, []string{"a"}),
	} {
		if Filter(kv) {
			t.Errorf("Filter kept %s", kv.Key)
		}
	}
	if !Filter(attribute.String(KeyOrgID, "0193c5a0-0000-7000-8000-000000000001")) || !Filter(attribute.Int64(KeyDuration, 5)) {
		t.Fatal("Filter dropped an allowed attribute")
	}

	// Spans: a disallowed attribute, a status message and an event never
	// reach the wire.
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	_, span := tp.Tracer("t").Start(context.Background(), "op")
	span.SetAttributes(attribute.String("email", "a@example.com"), attribute.String(KeyCode, "ok"))
	span.AddEvent("secret event")
	span.SetStatus(codes.Error, "token=abc")
	span.End()
	td := tracesData(resourceOf("svc", ""), rec.Ended())
	got := td.ResourceSpans[0].ScopeSpans[0].Spans[0]
	if len(got.Attributes) != 1 || got.Attributes[0].Key != KeyCode {
		t.Fatalf("span attributes = %v", got.Attributes)
	}
	if got.Status.Message != "" || len(got.Events) != 0 {
		t.Fatalf("status message or events exported: %v", got)
	}

	// Metrics: the SDK view filter (as Setup installs it) and the converters.
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithView(sdkmetric.NewView(
		sdkmetric.Instrument{Name: "*"}, sdkmetric.Stream{AttributeFilter: Filter})))
	c, err := mp.Meter("t").Int64Counter("pc_test_total")
	if err != nil {
		t.Fatal(err)
	}
	c.Add(context.Background(), 1, metric.WithAttributes(attribute.String("email", "a@example.com"), attribute.String(KeyScope, "signup")))
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	md := metricsData(resourceOf("svc", ""), &rm)
	dp := md.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetSum().DataPoints[0]
	if len(dp.Attributes) != 1 || dp.Attributes[0].Key != KeyScope {
		t.Fatalf("metric attributes = %v", dp.Attributes)
	}
	var b strings.Builder
	if err := writeText(&b, &rm); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "email") || !strings.Contains(b.String(), `pc_test_total{scope="signup"} 1`) {
		t.Fatalf("/metrics text:\n%s", b.String())
	}
}
