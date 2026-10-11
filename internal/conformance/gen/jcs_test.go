// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// esc writes the JSON escape \uXXXX without putting one in this file.
func esc(hex4 string) string { return string(rune(0x5c)) + "u" + hex4 }

// JCSCase is one RFC 8785 canonicalization: input to canonical bytes, or a
// refusal every implementation must share.
type JCSCase struct {
	Name string `json:"name"`
	// Input is the JSON text; InputHex replaces it when the bytes are not
	// valid UTF-8.
	Input    string `json:"input,omitzero"`
	InputHex string `json:"input_hex,omitzero"`
	// Canonical and SHA256 (lowercase hex of the canonical bytes) are set
	// when the input is accepted.
	Canonical string `json:"canonical,omitzero"`
	SHA256    string `json:"sha256,omitzero"`
	// Reject says why the input must be refused.
	Reject string `json:"reject,omitzero"`
}

// JCSFile is jcs.json.
type JCSFile struct {
	header
	Cases []JCSCase `json:"cases"`
}

func buildJCS(t *testing.T) any {
	t.Helper()
	keys := `{"` + esc("20ac") + `":"euro","` + esc("000d") + `":"cr","` + esc("fb33") + `":"hebrew","1":"one","` +
		esc("d83d") + esc("de00") + `":"emoji","` + esc("0080") + `":"c1","` + esc("00f6") + `":"o"}`
	cases := []struct{ name, input, reject string }{
		{"object members sorted by UTF-16 code units, not code points", keys, ""},
		{"negative zero is 0", `[-0,0.0,-0.0,0e10]`, ""},
		{"exponents at the ES6 boundaries", `[1e21,1e20,123456789012345678901,1E+2,1e-7,0.000001,1E-6]`, ""},
		{"shortest round-trip floats", `[0.1,1.5e300,-1.2345678901234567e-20,4.50,5e-324,1.7976931348623157e308]`, ""},
		{"integers beyond 2^53 become the nearest double", `[9007199254740993,-9007199254740993]`, ""},
		{"string escapes", `{"s":"` + esc("000f") + `\b\t\n\f\r\"\\\/` + esc("007f") + esc("2028") + esc("2029") + `"}`, ""},
		{"non-ASCII escapes become UTF-8", `{"name":"Gr` + esc("00fc") + esc("00df") + `e ` + esc("d83d") + esc("de00") + `"}`, ""},
		{"whitespace and nesting", " {\n \"b\" : [ true , false , null , { } , [ ] ] ,\r\n\t\"a\" : { \"z\" : 1 , \"y\" : \"\" } } ", ""},
		{"a lone high surrogate", `{"a":"` + esc("d800") + `"}`, "a lone surrogate is not a Unicode scalar value"},
		{"a lone low surrogate", `["` + esc("dc00") + `"]`, "a lone surrogate is not a Unicode scalar value"},
		{"reversed surrogates", `["` + esc("de00") + esc("d83d") + `"]`, "a lone surrogate is not a Unicode scalar value"},
		{"a duplicate member", `{"a":1,"a":2}`, "duplicate object member names"},
		{"a duplicate member after unescaping", `{"a":1,"` + esc("0061") + `":2}`, "duplicate object member names"},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", "invalid UTF-8"},
		{"a trailing comma", `{"a":1,}`, "not JSON"},
		{"a leading zero", `[01]`, "not JSON"},
		{"two values", `{} {}`, "not one JSON value"},
		{"nesting deeper than 10000", strings.Repeat("[", 10001) + strings.Repeat("]", 10001), "nesting deeper than 10000"},
	}
	f := JCSFile{header: head("jcs", "encoding/json/jsontext Value.Canonicalize (actionir, approval bindings, packages)",
		"RFC 8785 canonical JSON as PantherClaw computes it. An SDK's canonicalizer must give exactly canonical for every "+
			"accepted input and refuse every rejected one.")}
	for _, c := range cases {
		v := jsontext.Value(c.input)
		err := v.Canonicalize()
		jc := JCSCase{Name: c.name, Input: c.input}
		if !utf8.ValidString(c.input) {
			jc.Input, jc.InputHex = "", hex.EncodeToString([]byte(c.input))
		}
		switch {
		case c.reject != "" && err == nil:
			t.Fatalf("%s: canonicalized, want a refusal", c.name)
		case c.reject == "" && err != nil:
			t.Fatalf("%s: %v", c.name, err)
		case c.reject != "":
			jc.Reject = c.reject
		default:
			jc.Canonical, jc.SHA256 = string(v), sha256Hex(v)
		}
		f.Cases = append(f.Cases, jc)
	}
	return f
}

// ActionCase is one ActionIR: its canonical bytes and action hash, or a
// refusal under the rule it names (PAP-1 §6, HR-100..103) that every
// SDK's ActionIR parser must share.
type ActionCase struct {
	Name string `json:"name"`
	// Input is the JSON text; InputHex replaces it when the bytes are not
	// valid UTF-8.
	Input      string `json:"input,omitzero"`
	InputHex   string `json:"input_hex,omitzero"`
	Canonical  string `json:"canonical,omitzero"`
	ActionHash string `json:"action_hash,omitzero"`
	// Reject names the hardening rule that refuses the input.
	Reject string `json:"reject,omitzero"`
}

// ActionFile is actionir.json.
type ActionFile struct {
	header
	Cases []ActionCase `json:"cases"`
}

// goldens returns the mapping goldens (channel and tool, canonical
// ActionIR), checking each hash with actionir.Parse.
func goldens(t *testing.T) (names, actions []string) {
	t.Helper()
	for _, file := range []string{"mock-payments.actionir", "pc-shell.actionir"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "definitions", "mapping", "testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		for i := 0; i+1 < len(lines); i += 2 {
			fields := strings.Fields(lines[i])
			p, err := actionir.Parse([]byte(lines[i+1]))
			if err != nil || p.HashHex() != fields[len(fields)-1] {
				t.Fatalf("%s line %d: %v (hash %s)", file, i+1, err, p.HashHex())
			}
			names = append(names, strings.Join(fields[:len(fields)-1], " "))
			actions = append(actions, lines[i+1])
		}
	}
	return names, actions
}

// sdkAction is the first refund golden as the /sdk face maps it: channel
// sdk, through a connection.
func sdkAction(t *testing.T) actionir.Parsed {
	t.Helper()
	_, actions := goldens(t)
	p, err := actionir.Parse([]byte(actions[0]))
	if err != nil {
		t.Fatal(err)
	}
	a := p.Action
	a.Channel, a.Connection = "sdk", "01920000-0000-7000-8000-000000000007"
	out, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func buildActionIR(t *testing.T) any {
	t.Helper()
	f := ActionFile{header: head("actionir", "internal/actionir Parse over internal/definitions/mapping/testdata",
		"ActionIR v1 (PAP-1 §6): action_hash = lowercase hex SHA-256 of the RFC 8785 form. Inputs have every object's "+
			"members reversed and whitespace added.")}
	names, actions := goldens(t)
	names, actions = append(names, "sdk channel through a connection"), append(actions, string(sdkAction(t).Canonical))
	// An optional member written null is accepted and kept in the canonical
	// form, as PantherClaw parses it.
	withNull := strings.Replace(actions[0], `"channel":"mcp"`, `"channel":"mcp","connection":null`, 1)
	names, actions = append(names, "an optional member written null"), append(actions, withNull)
	for i, a := range actions {
		p, err := actionir.Parse([]byte(scramble(t, a)))
		if err != nil {
			t.Fatalf("%s: %v", names[i], err)
		}
		f.Cases = append(f.Cases, ActionCase{Name: names[i], Input: scramble(t, a), Canonical: string(p.Canonical), ActionHash: p.HashHex()})
	}
	base := actions[0]
	deep := `"reason":"duplicate","x":` + strings.Repeat(`{"x":`, 16) + `1` + strings.Repeat(`}`, 16)
	for _, r := range []struct{ name, from, to, rule string }{
		{"an unknown member", `{"action_id"`, `{"extra":true,"action_id"`, "HR-100"},
		{"a duplicate member", `"v":1}`, `"v":1,"v":1}`, "HR-100"},
		{"invalid UTF-8 in params", `"reason":"duplicate"`, "\"reason\":\"dup\xfflicate\"", "HR-100"},
		{"a lone surrogate in params", `"reason":"duplicate"`, `"reason":"` + esc("d800") + `"`, "HR-100"},
		{"nesting deeper than 16", `"reason":"duplicate"`, deep, "HR-100"},
		{"a string longer than 64 KiB", `"reason":"duplicate"`, `"reason":"` + strings.Repeat("d", 64<<10+1) + `"`, "HR-100"},
		{"a JSON number in params", `"value":"30.00"`, `"value":30.00`, "HR-101"},
		{"a version that is not 1", `"v":1}`, `"v":2}`, "HR-100"},
		{"a version written 1.0", `"v":1}`, `"v":1.0}`, "HR-100"},
		{"a version written 1e0", `"v":1}`, `"v":1e0}`, "HR-100"},
		{"a member name longer than 64 KiB", `"reason":"duplicate"`, `"reason":"duplicate","` + strings.Repeat("k", 64<<10+1) + `":"x"`, "HR-100"},
		{"nesting 5000 deep in params", `"reason":"duplicate"`, `"reason":"duplicate","x":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000), "HR-100"},
		{"a non-ASCII target id", `"id":"ch_1"`, `"id":"ch_` + esc("0441") + `"`, "HR-102"},
		{"a bidi control in the target id", `"id":"ch_1"`, `"id":"ch_1` + esc("202e") + `"`, "HR-102"},
		{"a space in the target id", `"id":"ch_1"`, `"id":"ch 1"`, "HR-102"},
		{"an identifier longer than 8 KiB", `"id":"ch_1"`, `"id":"ch_` + strings.Repeat("1", 8<<10) + `"`, "HR-102"},
		{"no destinations", `"destinations":[],`, ``, "HR-103"},
		{"no target id", `"id":"ch_1",`, ``, "HR-103"},
		{"an unknown channel", `"channel":"mcp"`, `"channel":"cli"`, "HR-103"},
		{"a definition without its digest", `"digest":"sha256:53b3effc5d6fc11070820fefd14806b01cdd6485d0e2a2136ff15925031fac43",`, ``, "HR-103"},
		{"a run id that is not a UUID", `"run_id":"01920000-0000-7000-8000-000000000003"`, `"run_id":"run-3"`, "HR-103"},
	} {
		in := strings.Replace(base, r.from, r.to, 1)
		if in == base {
			t.Fatalf("%s: %q not in the golden", r.name, r.from)
		}
		if _, err := actionir.Parse([]byte(in)); err == nil {
			t.Fatalf("%s: parsed, want a refusal", r.name)
		}
		c := ActionCase{Name: r.name, Input: in, Reject: r.rule}
		if !utf8.ValidString(in) {
			c.Input, c.InputHex = "", hex.EncodeToString([]byte(in))
		}
		f.Cases = append(f.Cases, c)
	}
	return f
}

// scramble returns JSON text v with every object's members reversed and
// whitespace added, so a canonicalizer has to sort and strip.
func scramble(t *testing.T, v string) string {
	t.Helper()
	d := jsontext.NewDecoder(strings.NewReader(v))
	var walk func() string
	walk = func() string {
		//exhaustive:ignore // only containers need walking; every other kind is copied as is
		switch d.PeekKind() {
		case '{', '[':
			open, err := d.ReadToken()
			if err != nil {
				t.Fatal(err)
			}
			var items []string
			for d.PeekKind() != '}' && d.PeekKind() != ']' {
				item := ""
				if open.Kind() == '{' {
					name, err := d.ReadValue()
					if err != nil {
						t.Fatal(err)
					}
					item = string(name) + " : "
				}
				items = append(items, item+walk())
			}
			if _, err := d.ReadToken(); err != nil {
				t.Fatal(err)
			}
			if open.Kind() == '{' {
				slices.Reverse(items)
				return "{ " + strings.Join(items, " ,\n  ") + " }"
			}
			return "[ " + strings.Join(items, " , ") + " ]"
		default:
			val, err := d.ReadValue()
			if err != nil {
				t.Fatal(err)
			}
			return string(val)
		}
	}
	return walk()
}
