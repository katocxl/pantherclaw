// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sigv4 signs HTTP requests with AWS Signature Version 4
// (AWS4-HMAC-SHA256, header-based). It is in-house so that S3-compatible
// export destinations and the AWS connector share one signer without an AWS
// SDK dependency (G0 M20 design decision 8). It is tested against AWS's
// published SigV4 test suite (testdata/aws4_testsuite).
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Algorithm is the only signing algorithm this package produces.
const Algorithm = "AWS4-HMAC-SHA256"

// UnsignedPayload is the payload hash S3 accepts for a body that is not
// hashed before sending (a streamed part whose integrity TLS carries).
const UnsignedPayload = "UNSIGNED-PAYLOAD"

// EmptyPayloadHash is the hex SHA-256 of an empty body.
const EmptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const (
	timeFormat = "20060102T150405Z"
	dateFormat = "20060102"

	headerDate          = "X-Amz-Date"
	headerSecurityToken = "X-Amz-Security-Token" //nolint:gosec // a header name, not a credential
	headerContentSHA256 = "X-Amz-Content-Sha256"
)

// Errors returned by Sign.
var (
	ErrNoCredentials = errors.New("sigv4: access key id and secret are required")
	ErrNoScope       = errors.New("sigv4: region and service are required")
	ErrNoHost        = errors.New("sigv4: request has no host")
	ErrPayloadHash   = errors.New("sigv4: payload hash must be hex SHA-256 or UNSIGNED-PAYLOAD")
)

// Credentials are the key pair, and for a temporary session its token.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// String never prints the secret or the session token.
func (c Credentials) String() string { return "sigv4.Credentials{" + c.AccessKeyID + "}" }

// Signer holds the credential scope. The zero value is not usable.
type Signer struct {
	Region  string
	Service string
	// S3 selects Amazon S3's canonicalisation: the path is encoded once and
	// never normalised, and X-Amz-Content-Sha256 is always sent.
	S3 bool
}

// unsignedHeaders are never part of SignedHeaders: proxies and the transport
// may change them in flight.
var unsignedHeaders = map[string]bool{
	"authorization":   true,
	"user-agent":      true,
	"x-amzn-trace-id": true,
	"expect":          true,
	"connection":      true,
	"content-length":  true,
	"accept-encoding": true,
}

// Sign adds X-Amz-Date, the session token (when present), for S3
// X-Amz-Content-Sha256, and the Authorization header to req. payloadHash is
// the hex SHA-256 of the body (HashPayload), or UnsignedPayload. For S3 the
// request path is rewritten to its canonical encoding, so what is sent is
// what was signed.
func (s Signer) Sign(req *http.Request, creds Credentials, payloadHash string, now time.Time) error {
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return ErrNoCredentials
	}
	if s.Region == "" || s.Service == "" {
		return ErrNoScope
	}
	if !validPayloadHash(payloadHash) {
		return ErrPayloadHash
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host == "" {
		return ErrNoHost
	}
	if req.Header == nil {
		req.Header = http.Header{}
	}
	t := now.UTC()
	req.Header.Set(headerDate, t.Format(timeFormat))
	if creds.SessionToken != "" {
		req.Header.Set(headerSecurityToken, creds.SessionToken)
	}
	path := req.URL.EscapedPath()
	if s.S3 {
		req.Header.Set(headerContentSHA256, payloadHash)
		path = encodePath(req.URL.Path)
		if path == "" {
			path = "/"
		}
		req.URL.RawPath = path
	}

	lines := []string{"host:" + host}
	for name, values := range req.Header {
		lc := strings.ToLower(name)
		if unsignedHeaders[lc] || lc == "host" {
			continue
		}
		lines = append(lines, lc+":"+strings.Join(values, "\x00"))
	}
	hdrs := headerList(lines)
	creq := s.canonicalRequest(req.Method, path, req.URL.RawQuery, hdrs, payloadHash)
	req.Header.Set("Authorization", s.authorization(creds, t, hdrs, creq))
	return nil
}

// HashPayload returns the hex SHA-256 of b for Sign.
func HashPayload(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func validPayloadHash(h string) bool {
	if h == UnsignedPayload {
		return true
	}
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil && strings.ToLower(h) == h
}

// header is one canonical header: a lower-case name and its values.
type header struct {
	name   string
	values []string
}

// headerList builds canonical headers from "Name:value" lines. Values of a
// repeated name keep their order; a NUL separates values that came from one
// http.Header entry.
func headerList(lines []string) []header {
	idx := map[string]int{}
	var out []header
	for _, l := range lines {
		name, value, _ := strings.Cut(l, ":")
		name = strings.ToLower(strings.TrimSpace(name))
		i, ok := idx[name]
		if !ok {
			i = len(out)
			idx[name] = i
			out = append(out, header{name: name})
		}
		out[i].values = append(out[i].values, strings.Split(value, "\x00")...)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out
}

func (s Signer) canonicalRequest(method, path, rawQuery string, hdrs []header, payloadHash string) string {
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(s.canonicalURI(path))
	b.WriteByte('\n')
	b.WriteString(canonicalQuery(rawQuery))
	b.WriteByte('\n')
	for _, h := range hdrs {
		b.WriteString(h.name)
		b.WriteByte(':')
		vs := make([]string, len(h.values))
		for i, v := range h.values {
			vs[i] = trimAll(v)
		}
		b.WriteString(strings.Join(vs, ","))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.WriteString(signedHeaders(hdrs))
	b.WriteByte('\n')
	b.WriteString(payloadHash)
	return b.String()
}

func signedHeaders(hdrs []header) string {
	names := make([]string, len(hdrs))
	for i, h := range hdrs {
		names[i] = h.name
	}
	return strings.Join(names, ";")
}

// canonicalURI encodes the path as sent. Services other than S3 normalise it
// and encode it again (so each segment ends up encoded twice); S3's path is
// already in canonical form (Sign set it).
func (s Signer) canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	if s.S3 {
		return path
	}
	return encodePath(normalizePath(path))
}

// normalizePath removes dot segments and empty segments, keeping a trailing
// slash (RFC 3986 §5.2.4, plus AWS's collapse of repeated slashes).
func normalizePath(p string) string {
	trailing := strings.HasSuffix(p, "/")
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	r := "/" + strings.Join(out, "/")
	if trailing && len(out) > 0 {
		r += "/"
	}
	return r
}

func encodePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = uriEncode(seg)
	}
	return strings.Join(segs, "/")
}

// canonicalQuery decodes each parameter, encodes it with AWS's rules and
// sorts by name, then value.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var params []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		params = append(params, kv{uriEncode(unescape(k)), uriEncode(unescape(v))})
	}
	sort.Slice(params, func(a, b int) bool {
		if params[a].k != params[b].k {
			return params[a].k < params[b].k
		}
		return params[a].v < params[b].v
	})
	out := make([]string, len(params))
	for i, p := range params {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

// unescape decodes %XX sequences and leaves anything malformed as it is. A
// '+' stays a '+': AWS does not treat it as a space.
func unescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b = append(b, unhex(s[i+1])<<4|unhex(s[i+2]))
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// uriEncode percent-encodes every byte except the unreserved characters
// A-Z a-z 0-9 - . _ ~, with upper-case hex.
func uriEncode(s string) string {
	const hexUpper = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexUpper[c>>4])
		b.WriteByte(hexUpper[c&15])
	}
	return b.String()
}

// trimAll trims a header value and collapses runs of spaces, tabs and folded
// line breaks into one space.
func trimAll(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

func (s Signer) scope(t time.Time) string {
	return t.Format(dateFormat) + "/" + s.Region + "/" + s.Service + "/aws4_request"
}

func (s Signer) stringToSign(t time.Time, creq string) string {
	sum := sha256.Sum256([]byte(creq))
	return Algorithm + "\n" + t.Format(timeFormat) + "\n" + s.scope(t) + "\n" + hex.EncodeToString(sum[:])
}

func (s Signer) signature(secret string, t time.Time, sts string) string {
	k := hmacSHA256([]byte("AWS4"+secret), t.Format(dateFormat))
	k = hmacSHA256(k, s.Region)
	k = hmacSHA256(k, s.Service)
	k = hmacSHA256(k, "aws4_request")
	return hex.EncodeToString(hmacSHA256(k, sts))
}

func (s Signer) authorization(creds Credentials, t time.Time, hdrs []header, creq string) string {
	sig := s.signature(creds.SecretAccessKey, t, s.stringToSign(t, creq))
	return Algorithm + " Credential=" + creds.AccessKeyID + "/" + s.scope(t) +
		", SignedHeaders=" + signedHeaders(hdrs) + ", Signature=" + sig
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
