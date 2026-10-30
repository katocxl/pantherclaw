// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sigv4

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The credentials and scope every case of AWS's SigV4 test suite uses.
var suiteCreds = Credentials{
	AccessKeyID:     "AKIDEXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
}

var suiteSigner = Signer{Region: "us-east-1", Service: "service"}

type suiteRequest struct {
	method, path, query string
	headers             []string
	body                []byte
	date                time.Time
}

// parseSuiteRequest reads a .req file: a request line, headers (a line that
// starts with white space continues the previous header) and, after a blank
// line, the body.
func parseSuiteRequest(t *testing.T, raw string) suiteRequest {
	t.Helper()
	head, body, _ := strings.Cut(raw, "\n\n")
	lines := strings.Split(head, "\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) < 3 {
		t.Fatalf("request line %q", lines[0])
	}
	target := strings.Join(parts[1:len(parts)-1], " ")
	r := suiteRequest{method: parts[0], body: []byte(body)}
	r.path, r.query, _ = strings.Cut(target, "?")
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
			r.headers[len(r.headers)-1] += " " + strings.TrimSpace(l)
			continue
		}
		r.headers = append(r.headers, l)
		if name, v, _ := strings.Cut(l, ":"); strings.EqualFold(name, headerDate) {
			d, err := time.Parse(timeFormat, v)
			if err != nil {
				t.Fatalf("date %q: %v", v, err)
			}
			r.date = d
		}
	}
	return r
}

func readSuiteFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// TestSigV4Suite runs every case of AWS's published SigV4 test suite: the
// canonical request, the string to sign and the Authorization value must
// match byte for byte.
// Covers: F517
func TestSigV4Suite(t *testing.T) {
	root := filepath.Join("testdata", "aws4_testsuite")
	var cases []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
	if len(cases) < 30 {
		t.Fatalf("found %d suite cases, want the whole suite", len(cases))
	}
	for _, c := range cases {
		t.Run(filepath.Base(c), func(t *testing.T) {
			r := parseSuiteRequest(t, readSuiteFile(t, c+".req"))
			if filepath.Base(c) == "get-vanilla-with-session-token" {
				// In this case the signer adds the session token header
				// before signing, as Sign does; .sreq carries its value.
				r.headers = append(r.headers, sessionTokenHeader(t, readSuiteFile(t, c+".sreq")))
			}
			hdrs := headerList(r.headers)
			creq := suiteSigner.canonicalRequest(r.method, r.path, r.query, hdrs, HashPayload(r.body))
			if want := readSuiteFile(t, c+".creq"); creq != want {
				t.Fatalf("canonical request\n got: %q\nwant: %q", creq, want)
			}
			sts := suiteSigner.stringToSign(r.date, creq)
			if want := readSuiteFile(t, c+".sts"); sts != want {
				t.Fatalf("string to sign\n got: %q\nwant: %q", sts, want)
			}
			authz := suiteSigner.authorization(suiteCreds, r.date, hdrs, creq)
			if want := readSuiteFile(t, c+".authz"); authz != want {
				t.Fatalf("authorization\n got: %q\nwant: %q", authz, want)
			}
		})
	}
}

func sessionTokenHeader(t *testing.T, sreq string) string {
	t.Helper()
	for _, l := range strings.Split(sreq, "\n") {
		if name, _, _ := strings.Cut(l, ":"); strings.EqualFold(name, headerSecurityToken) {
			return l
		}
	}
	t.Fatal("no session token in .sreq")
	return ""
}

// TestSignRequest signs a real *http.Request and gets the suite's
// get-vanilla Authorization.
// Covers: F517
func TestSignRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	req.Header.Set("User-Agent", "not-signed")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	if err := suiteSigner.Sign(req, suiteCreds, EmptyPayloadHash, now); err != nil {
		t.Fatal(err)
	}
	want := readSuiteFile(t, filepath.Join("testdata", "aws4_testsuite", "get-vanilla", "get-vanilla.authz"))
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// TestSignSessionToken signs the token header, as the suite's
// post-sts-header-before case does.
// Covers: F517
func TestSignSessionToken(t *testing.T) {
	dir := filepath.Join("testdata", "aws4_testsuite", "post-sts-token", "post-sts-header-before")
	r := parseSuiteRequest(t, readSuiteFile(t, filepath.Join(dir, "post-sts-header-before.req")))
	var token string
	for _, h := range r.headers {
		if name, v, _ := strings.Cut(h, ":"); strings.EqualFold(name, headerSecurityToken) {
			token = v
		}
	}
	req, _ := http.NewRequest(http.MethodPost, "https://example.amazonaws.com/", nil)
	creds := suiteCreds
	creds.SessionToken = token
	if err := suiteSigner.Sign(req, creds, EmptyPayloadHash, r.date); err != nil {
		t.Fatal(err)
	}
	if got, want := req.Header.Get("Authorization"), readSuiteFile(t, filepath.Join(dir, "post-sts-header-before.authz")); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if req.Header.Get(headerSecurityToken) != token {
		t.Fatal("session token header not set")
	}
}

// TestSignS3 reproduces the GET Object example of Amazon S3's SigV4
// documentation (header-based authentication): S3 paths are encoded once
// and X-Amz-Content-Sha256 is signed.
// Covers: F517
func TestSignS3(t *testing.T) {
	s := Signer{Region: "us-east-1", Service: "s3", S3: true}
	creds := Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	if err := s.Sign(req, creds, EmptyPayloadHash, time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " +
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

// TestS3PathEncoding: an S3 key is encoded once with AWS's rules and the
// request is sent with exactly that path.
func TestS3PathEncoding(t *testing.T) {
	s := Signer{Region: "eu-west-1", Service: "s3", S3: true}
	req, _ := http.NewRequest(http.MethodPut, "https://b.s3.amazonaws.com/a//b/$x y+z", nil)
	if err := s.Sign(req, suiteCreds, UnsignedPayload, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, want := req.URL.EscapedPath(), "/a//b/%24x%20y%2Bz"; got != want {
		t.Fatalf("path %q, want %q", got, want)
	}
	if req.Header.Get(headerContentSHA256) != UnsignedPayload {
		t.Fatal("payload hash header missing")
	}
}

func TestSignRefusesBadInput(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	now := time.Now()
	if err := suiteSigner.Sign(req, Credentials{}, EmptyPayloadHash, now); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("no creds: %v", err)
	}
	if err := (Signer{}).Sign(req, suiteCreds, EmptyPayloadHash, now); !errors.Is(err, ErrNoScope) {
		t.Fatalf("no scope: %v", err)
	}
	if err := suiteSigner.Sign(req, suiteCreds, "abc", now); !errors.Is(err, ErrPayloadHash) {
		t.Fatalf("bad hash: %v", err)
	}
	if strings.Contains(suiteCreds.String(), suiteCreds.SecretAccessKey) {
		t.Fatal("String prints the secret")
	}
}
