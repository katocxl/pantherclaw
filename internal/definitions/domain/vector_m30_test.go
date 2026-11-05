// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"encoding/json/jsontext"
	"math"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
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
	vals, err := def.DecodeParams(jsontext.Value(`{"id":"a","content":"c","embedding":` + canon(t, 0.5, -1, 2e-3) + `,"metadata":{"source.kind":"wiki"}}`))
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
		"empty embedding": `{"id":"a","content":"c","embedding":""}`,
		"a number list":   `{"id":"a","content":"c","embedding":[1]}`,
		"bad key":         `{"id":"a","content":"c","embedding":` + canon(t, 1) + `,"metadata":{"1x":"v"}}`,
		"long value":      `{"id":"a","content":"c","embedding":` + canon(t, 1) + `,"metadata":{"k":"` + strings.Repeat("v", 1025) + `"}}`,
		"over 8 KiB":      `{"id":"a","content":"c","embedding":` + canon(t, 1) + `,"metadata":{` + bigMap(9) + `}}`,
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

// canon is the canonical ActionIR form of fs, quoted (G0 M30 D1211).
func canon(t *testing.T, fs ...float64) string {
	t.Helper()
	return `"` + canonOf(t, fs) + `"`
}

func canonOf(t *testing.T, fs []float64) string {
	t.Helper()
	s, err := domain.EncodeFloat32s(fs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestHR704_AFloatArrayIsOneCanonicalString (G0 M30 D1211): the canonical
// form round-trips byte for byte; NaN, infinities, a float32 overflow, an
// empty list and too many items have no form, and a string that is not
// exactly the canonical form is refused.
func TestHR704_AFloatArrayIsOneCanonicalString(t *testing.T) {
	if got := canonOf(t, []float64{math.MaxFloat32}); got != "//9/fw==" {
		t.Fatalf("MaxFloat32 is %q", got)
	}
	in := []float64{0.5, -1, 2e-3, 3.4e38, -1.5e-45}
	s := canonOf(t, in)
	back, err := domain.DecodeFloat32s(s)
	if err != nil {
		t.Fatal(err)
	}
	if again := canonOf(t, back); again != s || len(back) != len(in) || back[0] != 0.5 || back[1] != -1 {
		t.Fatalf("round trip %q -> %v -> %q", s, back, again)
	}
	for name, fs := range map[string][]float64{
		"NaN":         {math.NaN()},
		"+Inf":        {math.Inf(1)},
		"-Inf":        {math.Inf(-1)},
		"overflow":    {3.5e38},
		"empty":       {},
		"16001 items": make([]float64, domain.MaxFloatItems+1),
	} {
		if _, err := domain.EncodeFloat32s(fs); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	for name, bad := range map[string]string{
		"no padding":        strings.TrimRight(canonOf(t, []float64{1}), "="),
		"url alphabet":      "__9_fw==", // MaxFloat32 is "//9/fw=="
		"ragged length":     "AAAAAAA=",
		"NaN bits":          "AADAfw==",
		"not base64":        "!!!!",
		"non-zero pad bits": "AAAAAB==",
	} {
		if _, err := domain.DecodeFloat32s(bad); err == nil {
			t.Errorf("%s: %q decoded", name, bad)
		}
	}
}
