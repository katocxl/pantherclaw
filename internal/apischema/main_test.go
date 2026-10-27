// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const sample = `{
  "paths": {
    "/x.v1.S/List": {
      "post": {
        "requestBody": {
          "content": {}
        },
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/x.v1.S/Get": {
      "get": {
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    }
  },
  "components": {
    "schemas": {
      "x.v1.Req": {
        "type": "object",
        "properties": {
          "pageSize": {
            "type": "integer",
            "title": "page_size",
            "maximum": 200,
            "format": "int32"
          },
          "days": {
            "type": "integer",
            "title": "days",
            "minimum": 1
          },
          "note": {
            "type": "string",
            "description": "a \u003cb\u003e \u0026 c"
          }
        }
      }
    }
  }
}`

func TestFixAddsZeroMinimumAnd415(t *testing.T) {
	out, err := Fix([]byte(sample), map[field]bool{{"x.v1.Req", "pageSize"}: true, {"x.v1.Absent", "n"}: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths      map[string]map[string]struct{ Responses map[string]map[string]any }
		Components struct {
			Schemas map[string]struct{ Properties map[string]map[string]any }
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc.Components.Schemas["x.v1.Req"].Properties
	if got := props["pageSize"]["minimum"]; got != float64(0) {
		t.Fatalf("pageSize minimum = %v, want 0", got)
	}
	if got := props["days"]["minimum"]; got != float64(1) {
		t.Fatalf("days (gte 1) minimum = %v, want untouched 1", got)
	}
	if _, ok := props["note"]["minimum"]; ok {
		t.Fatal("an unlisted field gained a minimum")
	}
	if got := doc.Paths["/x.v1.S/List"]["post"].Responses["415"]["description"]; got != unsupportedMedia {
		t.Fatalf("415 = %v", got)
	}
	if _, ok := doc.Paths["/x.v1.S/Get"]["get"].Responses["415"]; ok {
		t.Fatal("an operation without a request body gained a 415")
	}
	if !strings.Contains(string(out), `"maximum": 200,
            "minimum": 0,
            "format": "int32"`) {
		t.Fatalf("minimum not placed after maximum:\n%s", out)
	}
	again, err := Fix(out, map[field]bool{{"x.v1.Req", "pageSize"}: true})
	if err != nil || string(again) != string(out) {
		t.Fatalf("Fix is not idempotent: %v", err)
	}
}

func TestFixKeepsFormatting(t *testing.T) {
	doc := `{
  "a": [],
  "b": {},
  "c": "\u003cx\u003e \u0026",
  "d": [
    1,
    true,
    null
  ]
}`
	out, err := Fix([]byte(`{"components":{"schemas":{}}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "{\n  \"components\": {\n    \"schemas\": {}\n  }\n}" {
		t.Fatalf("unexpected:\n%s", out)
	}
	n, err := parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	n.write(&buf, "")
	if buf.String() != doc {
		t.Fatalf("round trip changed the document:\n%s", buf.String())
	}
}

func TestFixRejectsMissingOrContradictingProperty(t *testing.T) {
	if _, err := Fix([]byte(sample), map[field]bool{{"x.v1.Req", "gone"}: true}); err == nil {
		t.Fatal("a missing property was accepted")
	}
	if _, err := Fix([]byte(sample), map[field]bool{{"x.v1.Req", "days"}: true}); err == nil {
		t.Fatal("a minimum contradicting gte 0 was accepted")
	}
}

func TestGteZero(t *testing.T) {
	i32 := func(r *validate.Int32Rules) *validate.FieldRules {
		return &validate.FieldRules{Type: &validate.FieldRules_Int32{Int32: r}}
	}
	for name, tc := range map[string]struct {
		rules *validate.FieldRules
		want  bool
	}{
		"gte 0":        {i32(&validate.Int32Rules{GreaterThan: &validate.Int32Rules_Gte{Gte: 0}}), true},
		"gte 1":        {i32(&validate.Int32Rules{GreaterThan: &validate.Int32Rules_Gte{Gte: 1}}), false},
		"gt 0":         {i32(&validate.Int32Rules{GreaterThan: &validate.Int32Rules_Gt{Gt: 0}}), false},
		"lte only":     {i32(&validate.Int32Rules{LessThan: &validate.Int32Rules_Lte{Lte: 200}}), false},
		"double gte 0": {&validate.FieldRules{Type: &validate.FieldRules_Double{Double: &validate.DoubleRules{GreaterThan: &validate.DoubleRules_Gte{Gte: 0}}}}, true},
		"string":       {&validate.FieldRules{Type: &validate.FieldRules_String_{String_: &validate.StringRules{MaxLen: proto.Uint64(5)}}}, false},
		"none":         {nil, false},
	} {
		if got := gteZero(tc.rules); got != tc.want {
			t.Errorf("%s: gteZero = %v, want %v", name, got, tc.want)
		}
	}
}

// The real descriptors: page_size has `gte: 0` and days has `gte: 1`.
func TestZeroMinimumsFromProtovalidate(t *testing.T) {
	got := zeroMinimums(protoregistry.GlobalFiles)
	if !got[field{"pantherclaw.v1.ListAgentsRequest", "pageSize"}] {
		t.Fatal("ListAgentsRequest.page_size (gte 0) missing")
	}
	if got[field{"pantherclaw.v1.ListUsageRequest", "days"}] {
		t.Fatal("ListUsageRequest.days (gte 1) listed")
	}
	for f := range got {
		if !strings.HasPrefix(f.schema, "pantherclaw.") && !strings.HasPrefix(f.schema, "opentelemetry.") {
			t.Fatalf("unexpected message %s", f.schema)
		}
	}
}

// The committed schema is what `task api:schema` produces.
func TestCommittedSchemaIsFixed(t *testing.T) {
	doc, err := os.ReadFile("../../docs/api/pantherclaw.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Fix(doc, zeroMinimums(protoregistry.GlobalFiles))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(doc) {
		t.Fatal("docs/api/pantherclaw.openapi.json is stale; run task api:schema")
	}
}
