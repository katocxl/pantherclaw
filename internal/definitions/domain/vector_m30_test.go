// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/jsontext"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	pcvectorstore "github.com/katocxl/pantherclaw/packages/pc-vectorstore"
)

// TestHR704_VectorParamsAndSchemasDecodeWithinBounds: pc.vectorstore
// decodes, its number-array and string-map input schemas included (G0 M34
// D1002a), and an embedding and a metadata map within bounds decode.
func TestHR704_VectorParamsAndSchemasDecodeWithinBounds(t *testing.T) {
	pkg, err := manifest.Decode(pcvectorstore.Package)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := pkg.Definition("vectorstore.records.upsert")
	vals, err := def.DecodeParams(jsontext.Value(`{"id":"a","content":"c","embedding":[0.5,-1,2e-3],"metadata":{"source.kind":"wiki"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(vals["embedding"].Floats) != 3 || vals["metadata"].Map["source.kind"] != "wiki" {
		t.Fatalf("values %+v", vals)
	}
}

// TestHR704_VectorParamsAndSchemasOutOfBoundsAreRefused: the declarations
// (max_items, max_keys, the schema forms) and the values (empty or long
// lists, bad keys, long values, a map over 8 KiB) are each refused.
func TestHR704_VectorParamsAndSchemasOutOfBoundsAreRefused(t *testing.T) {
	src := string(pcvectorstore.Package)
	for name, edit := range map[string][2]string{
		"max_items over 16000":        {"max_items: 16000", "max_items: 16001"},
		"max_keys over 32":            {"max_keys: 32", "max_keys: 33"},
		"minItems in number array":    {"maxItems: 16000\n", "maxItems: 16000\n              minItems: 1\n"},
		"maxProperties over 32":       {"maxProperties: 16", "maxProperties: 33"},
		"long string map values":      {"maxLength: 1024", "maxLength: 1025"},
		"number array of a non-float": {"            top_k:\n              type: integer", "            top_k:\n              type: array\n              maxItems: 3\n              items:\n                type: number"},
	} {
		changed := strings.Replace(src, edit[0], edit[1], 1)
		if changed == src {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := manifest.Decode([]byte(changed)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	pkg, err := manifest.Decode(pcvectorstore.Package)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := pkg.Definition("vectorstore.records.upsert")
	for name, params := range map[string]string{
		"empty embedding": `{"id":"a","content":"c","embedding":[]}`,
		"string in list":  `{"id":"a","content":"c","embedding":["1"]}`,
		"bad key":         `{"id":"a","content":"c","embedding":[1],"metadata":{"1x":"v"}}`,
		"long value":      `{"id":"a","content":"c","embedding":[1],"metadata":{"k":"` + strings.Repeat("v", 1025) + `"}}`,
		"over 8 KiB":      `{"id":"a","content":"c","embedding":[1],"metadata":{` + bigMap(9) + `}}`,
	} {
		if _, err := def.DecodeParams(jsontext.Value(params)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// bigMap is n members of 1000-byte values.
func bigMap(n int) string {
	var m []string
	for i := range n {
		m = append(m, `"k`+string(rune('a'+i))+`":"`+strings.Repeat("v", 1000)+`"`)
	}
	return strings.Join(m, ",")
}
