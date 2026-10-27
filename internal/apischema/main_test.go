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
        "parameters": [
          {
            "name": "Connect-Protocol-Version",
            "in": "header",
            "required": true
          },
          {
            "name": "Connect-Timeout-Ms",
            "in": "header"
          }
        ],
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/x.v1.Req"
              }
            }
          }
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
        "parameters": [
          {
            "name": "Connect-Timeout-Ms",
            "in": "header"
          }
        ],
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
      "connect-timeout-header": {
        "type": "number"
      },
      "x.v1.Sub": {
        "type": "object",
        "properties": {
          "kind": {
            "type": "string",
            "enum": [
              "A"
            ]
          }
        }
      },
      "x.v1.Resp": {
        "type": "object",
        "properties": {
          "n": {
            "type": "string"
          }
        }
      },
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
          "parent": {
            "$ref": "#/components/schemas/x.v1.Sub",
            "title": "parent"
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

func TestFixAddsZeroMinimumAnd415AndDropsTheTimeout(t *testing.T) {
	out, err := Fix([]byte(sample), map[field]bool{{"x.v1.Req", "pageSize"}: true, {"x.v1.Absent", "n"}: true}, map[field]bool{{"x.v1.Req", "days"}: true})
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
	var raw struct {
		Components struct {
			Schemas map[string]struct{ Properties map[string]map[string]any }
		}
	}
	if err := json.Unmarshal(out, &raw); err != nil {
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
	types := func(schema, prop string) string {
		b, _ := json.Marshal(map[string]any{"type": raw.Components.Schemas[schema].Properties[prop]["type"], "enum": raw.Components.Schemas[schema].Properties[prop]["enum"], "anyOf": raw.Components.Schemas[schema].Properties[prop]["anyOf"]})
		return string(b)
	}
	for _, c := range []struct{ schema, prop, want string }{
		{"x.v1.Req", "pageSize", `{"anyOf":null,"enum":null,"type":["integer","null"]}`},
		{"x.v1.Req", "days", `{"anyOf":null,"enum":null,"type":"integer"}`},
		{"x.v1.Req", "parent", `{"anyOf":[{"$ref":"#/components/schemas/x.v1.Sub"},{"type":"null"}],"enum":null,"type":null}`},
		{"x.v1.Sub", "kind", `{"anyOf":null,"enum":["A",null],"type":["string","null"]}`},
		{"x.v1.Resp", "n", `{"anyOf":null,"enum":null,"type":"string"}`},
	} {
		if got := types(c.schema, c.prop); got != c.want {
			t.Errorf("%s.%s = %s, want %s", c.schema, c.prop, got, c.want)
		}
	}
	if s := string(out); strings.Contains(s, "Connect-Timeout-Ms") || strings.Contains(s, "connect-timeout-header") ||
		!strings.Contains(s, "Connect-Protocol-Version") {
		t.Fatalf("Connect-Timeout-Ms not dropped alone:\n%s", s)
	}
	if strings.Contains(string(out), `"required": true`) {
		t.Fatalf("Connect-Protocol-Version is still required:\n%s", out)
	}
	if strings.Count(string(out), `"parameters"`) != 1 {
		t.Fatalf("an emptied parameters list was kept:\n%s", out)
	}
	if !strings.Contains(string(out), `"maximum": 200,
            "minimum": 0,
            "format": "int32"`) {
		t.Fatalf("minimum not placed after maximum:\n%s", out)
	}
	again, err := Fix(out, map[field]bool{{"x.v1.Req", "pageSize"}: true}, map[field]bool{{"x.v1.Req", "days"}: true})
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
	out, err := Fix([]byte(`{"components":{"schemas":{}}}`), nil, nil)
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
	if _, err := Fix([]byte(sample), map[field]bool{{"x.v1.Req", "gone"}: true}, nil); err == nil {
		t.Fatal("a missing property was accepted")
	}
	if _, err := Fix([]byte(sample), map[field]bool{{"x.v1.Req", "days"}: true}, nil); err == nil {
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

// The real descriptors: a uuid without IGNORE_IF_ZERO_VALUE refuses its
// default, a plain page token and an optional id do not.
func TestZeroInvalidFromProtovalidate(t *testing.T) {
	got, err := zeroInvalid(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	for f, want := range map[field]bool{
		{"pantherclaw.v1.ListAgentsRequest", "pageToken"}:     false,
		{"pantherclaw.v1.ListAgentsRequest", "teamId"}:        false,
		{"pantherclaw.v1.ListTeamsRequest", "businessUnitId"}: false,
		{"pantherclaw.v1.ListUsageRequest", "days"}:           true,
	} {
		if got[f] != want {
			t.Errorf("%v zero invalid = %v, want %v", f, got[f], want)
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
	invalid, err := zeroInvalid(protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Fix(doc, zeroMinimums(protoregistry.GlobalFiles), invalid)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(doc) {
		t.Fatal("docs/api/pantherclaw.openapi.json is stale; run task api:schema")
	}
}
