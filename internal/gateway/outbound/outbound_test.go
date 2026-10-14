// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outbound

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const (
	ghToken = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	custody = "s3cr3t-custody-value/with+chars="
)

func TestScanHeldSecretForms(t *testing.T) {
	held := [][]byte{[]byte(custody)}
	for name, in := range map[string]Input{
		"raw body":     {Body: []byte("not json " + custody)},
		"json value":   {Body: []byte(`{"a":{"b":"x ` + custody + `"}}`)},
		"std base64":   {Args: []byte(`{"content":"` + base64.StdEncoding.EncodeToString([]byte(custody)) + `"}`)},
		"url base64":   {Args: []byte(`{"content":"` + base64.RawURLEncoding.EncodeToString([]byte(custody)) + `"}`)},
		"query escape": {Query: url.Values{"q": {custody}}},
		"escaped path": {Path: "/x/" + url.PathEscape(custody)},
		"header":       {Header: http.Header{"X-Foo": {custody}}},
	} {
		if r := Scan(in, held); !r.HeldSecret || len(r.Findings) != 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestScanShortSecretsAreIgnored(t *testing.T) {
	if r := Scan(Input{Body: []byte("abcdefg")}, [][]byte{[]byte("abcdefg")}); r.HeldSecret {
		t.Fatal("a 7-byte secret was matched")
	}
	if r := Scan(Input{Body: []byte("abcdefgh")}, [][]byte{[]byte("abcdefgh")}); !r.HeldSecret {
		t.Fatal("an 8-byte secret was not matched")
	}
}

func TestScanFormats(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want []Finding
	}{
		{"github in json body", Input{Body: []byte(`{"files":[{"content":"token=` + ghToken + `"}]}`)}, []Finding{{"github_token", "body:/files/0/content"}}},
		{"fine grained", Input{Query: url.Values{"q": {"github_pat_" + strings.Repeat("A", 30)}}}, []Finding{{"github_token", "query:q"}}},
		{"private key arg", Input{Args: []byte(`{"content":"-----BEGIN RSA PRIVATE KEY-----\nMIIE"}`)}, []Finding{{"private_key", "arg:content"}}},
		{"aws", Input{Header: http.Header{"x-foo": {"AKIA" + strings.Repeat("A", 16)}}}, []Finding{{"aws_access_key", "header:X-Foo"}}},
		{"slack", Input{Body: []byte("xoxb-1234567890-abc")}, []Finding{{"slack_token", "body"}}},
		{"pantherclaw", Input{Args: []byte(`{"x":"pck_dev_` + strings.Repeat("a", 32) + `"}`)}, []Finding{{"pantherclaw_token", "arg:x"}}},
		{"path", Input{Path: "/" + ghToken}, []Finding{{"github_token", "path"}}},
		{
			"dedup and sort",
			Input{Args: []byte(`{"b":"` + ghToken + ` ` + ghToken + `","a":"AKIA` + strings.Repeat("B", 16) + `"}`)},
			[]Finding{{"aws_access_key", "arg:a"}, {"github_token", "arg:b"}},
		},
		{"clean", Input{Body: []byte(`{"a":"hello"}`), Path: "/repos/x"}, nil},
		{"short", Input{Body: []byte("ghp_short")}, nil},
	}
	for _, c := range cases {
		got := Scan(c.in, nil)
		if got.HeldSecret || !reflect.DeepEqual(got.Findings, c.want) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestScanCapsFindings(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := range 40 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"k` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `":"` + ghToken + `"`)
	}
	b.WriteString("}")
	if n := len(Scan(Input{Body: []byte(b.String())}, nil).Findings); n != MaxFindings {
		t.Fatalf("%d findings", n)
	}
}

func TestScanNeverReturnsTheValue(t *testing.T) {
	r := Scan(Input{Body: []byte(`{"a":"` + ghToken + `"}`)}, nil)
	for _, f := range r.Findings {
		if strings.Contains(f.Kind+f.Location, "abcdefgh") {
			t.Fatal("finding carries the value")
		}
	}
}

// FuzzOutboundScan (HR-225): no input panics the scan; a held secret in the
// body is always found; findings are sorted, unique, capped and never
// contain the scanned token.
func FuzzOutboundScan(f *testing.F) {
	f.Add([]byte(`{"a":"`+ghToken+`"}`), "q", "/p", []byte(`{"x":"y"}`), custody)
	f.Add([]byte(custody), "", "", []byte(`[`), custody)
	f.Fuzz(func(t *testing.T, body []byte, q, path string, args []byte, secret string) {
		held := [][]byte{[]byte(secret)}
		in := Input{Body: body, Query: url.Values{"q": {q}}, Path: path, Args: args, Header: http.Header{"X-A": {q}}}
		r := Scan(in, held)
		if len(secret) >= MinSecret && strings.Contains(string(body), secret) && !r.HeldSecret {
			t.Fatalf("held secret in body not found: %q", secret)
		}
		if r.HeldSecret && len(r.Findings) != 0 {
			t.Fatal("findings with a refusal")
		}
		if len(r.Findings) > MaxFindings {
			t.Fatal("too many findings")
		}
		for i := 1; i < len(r.Findings); i++ {
			a, b := r.Findings[i-1], r.Findings[i]
			if a == b || a.Kind > b.Kind || (a.Kind == b.Kind && a.Location > b.Location) {
				t.Fatalf("not sorted/unique: %v", r.Findings)
			}
		}
	})
}

func TestScanBase64Values(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("config: " + ghToken + "\n"))
	got := Scan(Input{Body: []byte(`{"message":"m","content":"` + enc + `"}`)}, nil).Findings
	if want := []Finding{{"github_token", "body:/content(base64)"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	url64 := base64.RawURLEncoding.EncodeToString([]byte("x " + ghToken))
	got = Scan(Input{Args: []byte(`{"content":"` + url64 + `"}`)}, nil).Findings
	if want := []Finding{{"github_token", "arg:content(base64)"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	// Two levels are not decoded.
	twice := base64.StdEncoding.EncodeToString([]byte(enc))
	if got := Scan(Input{Body: []byte(`{"c":"` + twice + `"}`)}, nil).Findings; len(got) != 0 {
		t.Fatalf("%v", got)
	}
	// Binary content is not text.
	bin := base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4})
	if got := Scan(Input{Body: []byte(`{"c":"` + bin + `"}`)}, nil).Findings; len(got) != 0 {
		t.Fatalf("%v", got)
	}
}
