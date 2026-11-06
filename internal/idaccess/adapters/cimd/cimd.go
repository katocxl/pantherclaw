// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package cimd reads OAuth Client ID Metadata Documents
// (draft-ietf-oauth-client-id-metadata-document-00), the way MCP clients
// identify themselves to an authorization server (G0 M26 D402).
//
// A document is read over HTTPS through the egress guard, at most 5 KB
// (§6.6), and must be JSON whose client_id is exactly the URL it was read
// from (§4.1). A document naming a shared secret, or any client
// authentication other than "none", is refused (§4.1; D408.2: no key from a
// metadata document is ever trusted, so clients are public and PKCE-bound).
// Every redirect URI must be an https URL or an http loopback URL, and
// carry no fragment. Valid documents are cached for the response's max-age,
// clamped to [1 minute, 1 hour], and not at all under no-store or no-cache;
// errors and invalid documents are never cached (§4.4).
package cimd

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// Draft is the revision this reader implements.
const Draft = "draft-ietf-oauth-client-id-metadata-document-00"

// MaxDocument is the largest document read (§6.6).
const MaxDocument = 5 << 10

// Cache bounds.
const (
	MinCache  = time.Minute
	MaxCache  = time.Hour
	maxCached = 1024
	maxURIs   = 10
	maxName   = 200
)

// ErrDocument reports a client whose document can't be read or is refused.
var ErrDocument = errors.New("cimd: client metadata document refused")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrDocument, fmt.Sprintf(format, a...))
}

// Reader implements ports.ClientDocuments.
type Reader struct {
	// Client reads documents. Nil is the egress client, which refuses
	// private and loopback addresses at dial time (HR-071, §6.5).
	Client *http.Client
	// CheckURL checks a client URL before it is read; nil is
	// oidcrp.CheckOrgURL (HTTPS on a public host).
	CheckURL func(string) error
	Clock    clock.Clock

	once  sync.Once
	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	md    ports.ClientMetadata
	until time.Time
}

func (r *Reader) init() {
	r.once.Do(func() {
		if r.Client == nil {
			r.Client = httpx.NewEgressClient(httpx.EgressConfig{Timeout: 10 * time.Second})
		}
		if r.CheckURL == nil {
			r.CheckURL = oidcrp.CheckOrgURL
		}
		if r.Clock == nil {
			r.Clock = clock.System{}
		}
		r.cache = map[string]cached{}
	})
}

// ValidClientID reports whether raw can be a client identifier (§3): https,
// a path, no dot segments, fragment, userinfo or query.
func ValidClientID(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(raw, "#") || len(u.EscapedPath()) < 2 || len(raw) > 1024 {
		return false
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/")[1:] {
		if seg == "." || seg == ".." || strings.EqualFold(seg, "%2e") || strings.EqualFold(seg, "%2e%2e") {
			return false
		}
	}
	return true
}

// validRedirect accepts an https URL, or an http loopback URL for native
// clients (RFC 8252 §7.3), with no fragment or userinfo.
func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil || len(raw) > 2048 {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "127.0.0.1" || h == "::1" || h == "localhost"
	}
	return false
}

// document is the part of the metadata this reader looks at.
type document struct {
	ClientID                *string  `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method"`
	ClientSecret            *string  `json:"client_secret"`
	ClientSecretExpiresAt   any      `json:"client_secret_expires_at"`
	// DPoPBound is RFC 9449 §5.2 client metadata (G0 M30 D911).
	DPoPBound bool `json:"dpop_bound_access_tokens"`
}

// Fetch implements ports.ClientDocuments.
func (r *Reader) Fetch(ctx context.Context, clientURL string) (ports.ClientMetadata, error) {
	r.init()
	if !ValidClientID(clientURL) {
		return ports.ClientMetadata{}, refuse("client id is not a valid URL")
	}
	now := r.Clock.Now()
	r.mu.Lock()
	c, ok := r.cache[clientURL]
	r.mu.Unlock()
	if ok && now.Before(c.until) {
		return c.md, nil
	}
	if err := r.CheckURL(clientURL); err != nil {
		return ports.ClientMetadata{}, refuse("client URL: %v", err)
	}
	md, ttl, err := r.read(ctx, clientURL)
	if err != nil {
		return ports.ClientMetadata{}, err
	}
	if ttl == 0 {
		return md, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxCached {
		r.cache = map[string]cached{}
	}
	r.cache[clientURL] = cached{md: md, until: now.Add(ttl)}
	return md, nil
}

func (r *Reader) read(ctx context.Context, clientURL string) (ports.ClientMetadata, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientURL, nil)
	if err != nil {
		return ports.ClientMetadata{}, 0, refuse("request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return ports.ClientMetadata{}, 0, refuse("unreachable")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ports.ClientMetadata{}, 0, refuse("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !jsonType(ct) {
		return ports.ClientMetadata{}, 0, refuse("content type %q", ct)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil || len(b) > MaxDocument {
		return ports.ClientMetadata{}, 0, refuse("document too large or unreadable")
	}
	md, err := Parse(b, clientURL)
	if err != nil {
		return ports.ClientMetadata{}, 0, err
	}
	return md, cacheFor(resp.Header.Get("Cache-Control")), nil
}

// Parse checks a document read from clientURL (§4.1).
func Parse(b []byte, clientURL string) (ports.ClientMetadata, error) {
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		return ports.ClientMetadata{}, refuse("not a JSON object")
	}
	switch {
	case d.ClientID == nil || *d.ClientID != clientURL:
		return ports.ClientMetadata{}, refuse("client_id is not the document's URL")
	case d.ClientSecret != nil || d.ClientSecretExpiresAt != nil:
		return ports.ClientMetadata{}, refuse("the document names a client secret")
	case d.TokenEndpointAuthMethod != nil && *d.TokenEndpointAuthMethod != "none":
		return ports.ClientMetadata{}, refuse("token_endpoint_auth_method must be none")
	case len(d.RedirectURIs) == 0 || len(d.RedirectURIs) > maxURIs:
		return ports.ClientMetadata{}, refuse("redirect_uris")
	}
	for _, u := range d.RedirectURIs {
		if !validRedirect(u) {
			return ports.ClientMetadata{}, refuse("redirect URI %q", u)
		}
	}
	name := strings.TrimSpace(d.ClientName)
	if len([]rune(name)) > maxName {
		name = string([]rune(name)[:maxName])
	}
	return ports.ClientMetadata{ClientID: clientURL, Name: name, RedirectURIs: d.RedirectURIs, DPoPBound: d.DPoPBound}, nil
}

func jsonType(ct string) bool {
	mt, _, _ := strings.Cut(strings.ToLower(ct), ";")
	mt = strings.TrimSpace(mt)
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

// cacheFor is the response's max-age clamped to [MinCache, MaxCache]; 0
// under no-store or no-cache.
func cacheFor(cc string) time.Duration {
	ttl := MinCache
	for d := range strings.SplitSeq(strings.ToLower(cc), ",") {
		d = strings.TrimSpace(d)
		if d == "no-store" || d == "no-cache" {
			return 0
		}
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	return min(max(ttl, MinCache), MaxCache)
}
