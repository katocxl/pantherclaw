// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package egress

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Response limits (G0 M6 design decision 11).
const (
	// DefaultMaxResponse is a connection's default response cap.
	DefaultMaxResponse = 1 << 20
	// MaxResponse is the largest cap a connection may set.
	MaxResponse = 8 << 20
	// maxRatio bounds gzip a target sends unasked: at most this many times
	// the compressed size.
	maxRatio = 20
)

// ErrHost reports a request for another scheme, host or port than the
// connection's: nothing is sent.
var ErrHost = errors.New("egress: the request leaves the connection's scheme, host and port")

// Response is a capped, decompressed target response.
type Response struct {
	Status int
	Body   []byte
	// Truncated: the body was longer than the cap and was cut.
	Truncated   bool
	ContentType string
	RequestID   string
}

// Client sends a connection's requests.
type Client struct {
	http     *http.Client
	scheme   string
	host     string
	maxBytes int64
}

// NewClient returns the client of one connection: the hardened egress
// client (no redirects, no proxies, connected-address checks, no client
// certificate; HR-070..074) with the operator's allowed prefixes, pinned to
// the base URL's scheme, host and port.
func NewClient(baseURL string, timeout time.Duration, maxBytes int32, allowed []netip.Prefix) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("egress: base URL %q", baseURL)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponse
	}
	return &Client{
		http:   httpx.NewEgressClient(httpx.EgressConfig{Timeout: timeout, AllowedPrefixes: allowed}),
		scheme: u.Scheme, host: u.Host, maxBytes: int64(min(maxBytes, MaxResponse)),
	}, nil
}

// HTTPRequest prepares an outbound request (the caller places the
// credential and sends it with Do). It refuses another scheme or host.
func (c *Client) HTTPRequest(ctx context.Context, r Request) (*http.Request, error) {
	if r.URL == nil || r.URL.Scheme != c.scheme || r.URL.Host != c.host {
		return nil, ErrHost
	}
	var body io.Reader = http.NoBody
	if r.Body != nil {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	if r.Body != nil {
		req.Header.Set("Content-Type", cmp.Or(r.ContentType, JSONContentType))
	}
	req.Header.Set("Accept-Encoding", "identity")
	for name, v := range r.Headers {
		// Literal static headers of the reviewed template, never a
		// reserved one (G0 M14 D8); the caller places the credential after.
		req.Header.Set(name, v)
	}
	if r.IdempotencyHeader != "" {
		req.Header.Set(r.IdempotencyHeader, r.IdempotencyKey)
	}
	return req, nil
}

// Do sends a prepared request and reads its response within the cap. An
// error before a response means nothing may have been received; the
// caller decides FAILED (nothing sent) or UNKNOWN.
func (c *Client) Do(req *http.Request) (Response, error) {
	if req.URL.Scheme != c.scheme || req.URL.Host != c.host {
		return Response{}, ErrHost
	}
	res, err := c.http.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = res.Body.Close() }()
	out := Response{Status: res.StatusCode, ContentType: res.Header.Get("Content-Type"), RequestID: requestID(res.Header)}
	raw, truncated, err := readCapped(res.Body, c.maxBytes)
	if err != nil {
		return out, err
	}
	out.Truncated = truncated
	if res.Header.Get("Content-Encoding") == "gzip" {
		raw, truncated, err = gunzip(raw, c.maxBytes)
		if err != nil {
			return out, err
		}
		out.Truncated = out.Truncated || truncated
	}
	out.Body = raw
	return out, nil
}

// ErrTooLarge reports a streamed response longer than the connection's cap.
var ErrTooLarge = errors.New("egress: the response is larger than the connection's cap")

// Open sends a prepared request and returns its response to be read as it
// arrives, such as an MCP event stream, which the caller closes. Reading
// past the connection's cap fails with ErrTooLarge, and a compressed body
// is refused (it was asked for identity).
func (c *Client) Open(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != c.scheme || req.URL.Host != c.host {
		return nil, ErrHost
	}
	res, err := c.http.Do(req) //nolint:gosec // G704: pinned to the connection above; the egress client checks the connected address (HR-070..074)
	if err != nil {
		return nil, err
	}
	if e := res.Header.Get("Content-Encoding"); e != "" && e != "identity" {
		_ = res.Body.Close()
		return nil, fmt.Errorf("egress: a %q body on a stream", e)
	}
	res.Body = &capped{rc: res.Body, left: c.maxBytes}
	return res, nil
}

// RequestID is the target's request id from response headers, if any.
func RequestID(h http.Header) string { return requestID(h) }

// capped reads at most left bytes and fails, rather than truncating, past
// them: a cut stream would be misread.
type capped struct {
	rc   io.ReadCloser
	left int64
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left <= 0 {
		var one [1]byte
		if n, err := c.rc.Read(one[:]); n > 0 {
			return 0, ErrTooLarge
		} else if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.rc.Read(p)
	c.left -= int64(n)
	return n, err
}

func (c *capped) Close() error { return c.rc.Close() }

func requestID(h http.Header) string {
	for _, k := range []string{"X-Request-Id", "Request-Id", "X-Amzn-Requestid"} {
		if v := h.Get(k); v != "" && len(v) <= 128 {
			return v
		}
	}
	return ""
}

// readCapped reads at most limit bytes and reports whether there was more.
func readCapped(r io.Reader, limit int64) ([]byte, bool, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > limit {
		return b[:limit], true, nil
	}
	return b, false, nil
}

// gunzip decompresses a body the target compressed although it was asked
// not to, within maxRatio times its size and the cap.
func gunzip(b []byte, limit int64) ([]byte, bool, error) {
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, false, fmt.Errorf("egress: a gzip body that does not decode: %w", err)
	}
	defer func() { _ = z.Close() }()
	bound := min(limit, int64(len(b))*maxRatio)
	out, truncated, err := readCapped(z, bound)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, err
	}
	return out, truncated, nil
}

// Redacted replaces the credential in a response body, in plain, base64
// (standard and URL alphabets, padded or not) and percent-encoded form,
// with [REDACTED] (HR-076). A credential shorter than 4 bytes is not
// searched for: it would match by chance.
func Redacted(body, secret []byte) []byte {
	if len(secret) < 4 {
		return body
	}
	forms := [][]byte{
		secret,
		[]byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawStdEncoding.EncodeToString(secret)),
		[]byte(base64.URLEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret)),
		[]byte(url.QueryEscape(string(secret))), []byte(url.PathEscape(string(secret))),
	}
	for _, f := range forms {
		body = bytes.ReplaceAll(body, f, []byte("[REDACTED]"))
	}
	return body
}
