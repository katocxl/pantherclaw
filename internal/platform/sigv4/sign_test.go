// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sigv4

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func suiteCases(t *testing.T) []string {
	t.Helper()
	var cases []string
	err := filepath.WalkDir(filepath.Join("testdata", "aws4_testsuite"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".req") {
			cases = append(cases, strings.TrimSuffix(p, ".req"))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

// suiteHTTPRequest builds the *http.Request Go would send for a .req case,
// or reports false when Go cannot send it as written: a path or query that
// Go would escape differently on the wire, or a folded header line.
func suiteHTTPRequest(t *testing.T, raw string) (*http.Request, suiteRequest, bool) {
	t.Helper()
	r := parseSuiteRequest(t, raw)
	head, _, _ := strings.Cut(raw, "\n\n")
	for _, l := range strings.Split(head, "\n")[1:] {
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
			return nil, r, false
		}
	}
	for _, c := range r.query {
		if c <= ' ' || c > '~' {
			return nil, r, false
		}
	}
	var host string
	for _, h := range r.headers {
		if name, v, _ := strings.Cut(h, ":"); strings.EqualFold(name, "host") {
			host = v
		}
	}
	u, err := url.Parse("https://" + host + r.path)
	if err != nil || u.EscapedPath() != r.path {
		return nil, r, false
	}
	u.RawQuery = r.query
	req, err := http.NewRequest(r.method, u.String(), bytes.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	for _, h := range r.headers {
		name, v, _ := strings.Cut(h, ":")
		if strings.EqualFold(name, "host") {
			continue
		}
		req.Header.Add(name, v)
	}
	return req, r, true
}

// TestSigV4SuiteThroughSign runs every suite case that Go can send through
// Sign with a real *http.Request: header collection from http.Header, the
// escaped path and the query as Go sends them, and the session token that
// Sign adds.
// Covers: F517
func TestSigV4SuiteThroughSign(t *testing.T) {
	ran := 0
	for _, c := range suiteCases(t) {
		name := filepath.Base(c)
		req, r, ok := suiteHTTPRequest(t, readSuiteFile(t, c+".req"))
		if !ok {
			t.Logf("%s: not representable as a Go request, canonical form covered by TestSigV4Suite", name)
			continue
		}
		ran++
		t.Run(name, func(t *testing.T) {
			creds := suiteCreds
			switch name {
			case "get-vanilla-with-session-token", "post-sts-header-before":
				// Sign adds the token itself; .sreq carries its value.
				_, v, _ := strings.Cut(sessionTokenHeader(t, readSuiteFile(t, c+".sreq")), ":")
				creds.SessionToken = v
			}
			if err := suiteSigner.Sign(req, creds, HashPayload(r.body), r.date); err != nil {
				t.Fatal(err)
			}
			if got, want := req.Header.Get("Authorization"), readSuiteFile(t, c+".authz"); got != want {
				t.Fatalf("authorization\n got: %q\nwant: %q", got, want)
			}
		})
	}
	if ran < 25 {
		t.Fatalf("only %d suite cases ran through Sign", ran)
	}
}

// TestSignNonS3DoubleEncodes: a path Go escapes on the wire is encoded again
// in the canonical request, as AWS requires for every service but S3.
func TestSignNonS3DoubleEncodes(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/example space/", nil)
	hdrs := headerList([]string{"host:example.amazonaws.com"})
	creq := suiteSigner.canonicalRequest(req.Method, req.URL.EscapedPath(), "", hdrs, EmptyPayloadHash)
	if !strings.HasPrefix(creq, "GET\n/example%2520space/\n") {
		t.Fatalf("canonical request %q", creq)
	}
}

// TestSignS3DocumentationExamples reproduces the examples of Amazon S3's
// SigV4 header-based authentication documentation: a PUT whose key has a
// special character ($, encoded once), and two GETs whose sub-resource and
// parameters exercise S3's query canonicalisation.
// Covers: F517
func TestSignS3DocumentationExamples(t *testing.T) {
	s := Signer{Region: "us-east-1", Service: "s3", S3: true}
	creds := Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const scope = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
	cases := []struct {
		name, method, url, body string
		headers                 map[string]string
		want                    string
		wirePath                string
	}{
		{
			name: "put-object-special-character", method: http.MethodPut,
			url: "https://examplebucket.s3.amazonaws.com/test$file.text", body: "Welcome to Amazon S3.",
			headers: map[string]string{"Date": "Fri, 24 May 2013 00:00:00 GMT", "X-Amz-Storage-Class": "REDUCED_REDUNDANCY"},
			want: scope + "SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, " +
				"Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
			wirePath: "/test%24file.text",
		},
		{
			name: "get-bucket-lifecycle", method: http.MethodGet, url: "https://examplebucket.s3.amazonaws.com/?lifecycle",
			want: scope + "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
				"Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
			wirePath: "/",
		},
		{
			name: "list-objects", method: http.MethodGet, url: "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			want: scope + "SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
				"Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
			wirePath: "/",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if err := s.Sign(req, creds, HashPayload([]byte(tc.body)), now); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get("Authorization"); got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
			if got := req.URL.EscapedPath(); got != tc.wirePath {
				t.Fatalf("sent path %q, signed %q", got, tc.wirePath)
			}
		})
	}
}

// TestSignS3RefusesDotSegments: S3 mode never signs a path a proxy or an
// S3-compatible server could normalise to another object.
func TestSignS3RefusesDotSegments(t *testing.T) {
	s := Signer{Region: "us-east-1", Service: "s3", S3: true}
	for _, p := range []string{"/x/../../etc", "/b/./k", "/b/..", "/."} {
		req, _ := http.NewRequest(http.MethodPut, "https://b.example", nil)
		req.URL.Path = p
		if err := s.Sign(req, suiteCreds, UnsignedPayload, time.Now()); !errors.Is(err, ErrDotSegment) {
			t.Fatalf("%s: %v", p, err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Fatalf("%s: signed anyway", p)
		}
	}
	// A dot inside a segment is an ordinary key.
	req, _ := http.NewRequest(http.MethodPut, "https://b.example/a.b/..c/.d", nil)
	if err := s.Sign(req, suiteCreds, UnsignedPayload, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestTrimAllASCIIOnly: header values collapse ASCII space, tab and folded
// line breaks only; Unicode white space is kept as AWS keeps it.
func TestTrimAllASCIIOnly(t *testing.T) {
	cases := map[string]string{
		"  a   b\t\tc  ":     "a b c",
		"value1\r\n  value2": "value1 value2",
		"pack title":         "pack title",
		"x\u0085y":           "x\u0085y",
		"   a":               "  a",
		"":                   "",
		"\t \t":              "",
		`"a   b   c"`:        `"a b c"`,
		"café  été":          "café été",
	}
	for in, want := range cases {
		if got := trimAll(in); got != want {
			t.Errorf("trimAll(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCredentialsNeverRender: the secret and the session token stay out of
// fmt, encoding/json and slog (text and JSON handlers), alone and embedded.
func TestCredentialsNeverRender(t *testing.T) {
	c := Credentials{AccessKeyID: "AKIDVISIBLE", SecretAccessKey: "SECRETVALUEX", SessionToken: "TOKENVALUEX"}
	type wrapper struct {
		Name  string
		Creds Credentials
	}
	w := wrapper{Name: "dest", Creds: c}
	var outs []string
	for _, f := range []string{"%v", "%s", "%+v", "%#v"} {
		outs = append(outs, fmt.Sprintf(f, c), fmt.Sprintf(f, w), fmt.Sprintf(f, &c))
	}
	for _, v := range []any{c, w, &c} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(b))
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "creds", c, "ptr", &c)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "creds", c, "ptr", &c)
	outs = append(outs, buf.String())
	for _, o := range outs {
		if strings.Contains(o, c.SecretAccessKey) || strings.Contains(o, c.SessionToken) {
			t.Fatalf("secret rendered: %s", o)
		}
		if !strings.Contains(o, c.AccessKeyID) && !strings.HasPrefix(o, "{") {
			t.Fatalf("access key id missing: %s", o)
		}
	}
}
