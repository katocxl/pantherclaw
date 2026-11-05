// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchors

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	"github.com/katocxl/pantherclaw/internal/payments/httpsig"
	"github.com/katocxl/pantherclaw/internal/payments/sandbox"
	"github.com/katocxl/pantherclaw/internal/payments/sdjwt"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Key fetching limits (D1121).
const (
	// MaxDocument caps a fetched key document.
	MaxDocument = 64 << 10
	// MaxKeys caps the keys kept from one document.
	MaxKeys = 20
	// CacheFor is how long fetched keys are used.
	CacheFor = time.Hour
	// MissInterval spaces refetches for an unknown kid.
	MissInterval = time.Minute
	// FetchTimeout bounds one fetch.
	FetchTimeout = 10 * time.Second
)

// DirectoryPath is the Web Bot Auth key directory path; an AGENT_DIRECTORY
// URL with another path is a key service queried as ?keyID= (Visa TAP).
const DirectoryPath = "/.well-known/http-message-signatures-directory"

// The sandbox host allow-list (D1120) lives in internal/payments/sandbox,
// shared with the connections and the gateway's merchant endpoint check
// (D1124c): empty, plus loopback for the simulator.

// loopback are the ranges the simulator's anchors reach (D1120).
var loopback = sandbox.Loopback

// isLoopbackHost reports whether h is localhost or a loopback literal.
func isLoopbackHost(h string) bool { return sandbox.IsLoopbackHost(h) }

// SandboxHost reports whether host may be named by an anchor URL.
func SandboxHost(host string) bool { return sandbox.Host(host) }

// CheckURL accepts an https URL without credentials or fragment on a
// sandbox host; ErrInvalid for a malformed URL and ap2.ErrLiveRefused for
// any other host.
func CheckURL(raw string) error {
	ok, isSandbox := sandbox.URL(raw)
	if !ok {
		return ErrInvalid
	}
	if !isSandbox {
		return ap2.ErrLiveRefused
	}
	return nil
}

// Anchor is the part of a trust anchor a verifier needs.
type Anchor struct {
	ID      ids.UUID
	Kind    ap2.Kind
	JWKS    []byte
	URL     string
	Sandbox bool
}

// key is one usable key of a document.
type key struct {
	kid        string
	thumbprint string
	pub        crypto.PublicKey
}

type entry struct {
	keys     []key
	at, miss time.Time
}

// KeySource fetches and caches anchors' keys through the egress client:
// no redirects, MaxDocument, CacheFor, and only sandbox hosts.
type KeySource struct {
	public, local *http.Client
	clock         clock.Clock
	log           *slog.Logger

	mu    sync.Mutex
	cache map[string]*entry
}

// KeyConfig configures a KeySource.
type KeyConfig struct {
	// RootCAs overrides the system roots (the simulator, tests).
	RootCAs *x509.CertPool
}

// NewKeySource returns a key source.
func NewKeySource(cfg KeyConfig, clk clock.Clock, log *slog.Logger) *KeySource {
	if log == nil {
		log = pclog.Discard()
	}
	if clk == nil {
		clk = clock.System{}
	}
	ec := httpx.EgressConfig{Timeout: FetchTimeout, RootCAs: cfg.RootCAs}
	lc := ec
	lc.AllowedPrefixes = loopback
	return &KeySource{
		public: httpx.NewEgressClient(ec), local: httpx.NewEgressClient(lc), clock: clk, log: log,
		cache: map[string]*entry{},
	}
}

// Resolver returns the verifier view of the given ACTIVE anchors. aud are
// the KB-JWT audiences accepted; with none ap2.Verify refuses every mandate
// (D1122b): wrap with ap2.WithAudiences.
func (s *KeySource) Resolver(active []Anchor, aud []string) *Resolver {
	return &Resolver{src: s, anchors: slices.Clone(active), aud: slices.Clone(aud)}
}

// Resolver implements ap2.Anchors and httpsig.Keys over a fixed set of
// ACTIVE anchors.
type Resolver struct {
	src     *KeySource
	anchors []Anchor
	aud     []string
}

var (
	_ ap2.Anchors  = (*Resolver)(nil)
	_ httpsig.Keys = (*Resolver)(nil)
)

// Audiences implements ap2.Anchors.
func (r *Resolver) Audiences() []string { return r.aud }

// Keys implements ap2.Anchors: the keys named kid of the anchors of kind.
func (r *Resolver) Keys(ctx context.Context, kind ap2.Kind, kid string) ([]ap2.AnchorKey, error) {
	var out []ap2.AnchorKey
	for _, a := range r.anchors {
		if a.Kind != kind {
			continue
		}
		ks, err := r.src.keys(ctx, a, a.URL, kid)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			if k.kid == kid {
				out = append(out, ap2.AnchorKey{AnchorID: a.ID, Key: k.pub})
			}
		}
	}
	return out, nil
}

// AgentKeys implements httpsig.Keys: the keys named keyid (a kid or an RFC
// 7638 thumbprint) of the AGENT_DIRECTORY anchors; with agent set, only of
// the anchor whose URL it names. agent itself is never fetched (D1123).
func (r *Resolver) AgentKeys(ctx context.Context, agent, keyid string) ([]httpsig.Key, error) {
	var out []httpsig.Key
	for _, a := range r.anchors {
		if a.Kind != ap2.KindAgentDirectory || (agent != "" && !namesAnchor(agent, a.URL)) {
			continue
		}
		src := a.URL
		if src != "" && !isDirectory(src) {
			src = keyServiceURL(src, keyid)
		}
		ks, err := r.src.keys(ctx, a, src, keyid)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			if k.kid == keyid || k.thumbprint == keyid {
				out = append(out, httpsig.Key{AnchorID: a.ID, Key: k.pub})
			}
		}
	}
	return out, nil
}

// namesAnchor reports whether a Signature-Agent value names the anchor
// URL: the URL itself, or the origin whose directory it is.
func namesAnchor(agent, anchorURL string) bool {
	if anchorURL == "" {
		return false
	}
	agent = strings.TrimSuffix(agent, "/")
	return agent == strings.TrimSuffix(anchorURL, "/") || agent+DirectoryPath == anchorURL
}

func isDirectory(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Path == DirectoryPath
}

// keyServiceURL is a key service URL with keyID set.
func keyServiceURL(raw, keyid string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set("keyID", keyid)
	u.RawQuery = q.Encode()
	return u.String()
}

// keys returns an anchor's keys from its static JWKS or src, from the
// cache when fresh. A fetch failure is logged and yields no keys (the
// verification then fails closed); a live anchor is ap2.ErrLiveRefused.
func (s *KeySource) keys(ctx context.Context, a Anchor, src, kid string) ([]key, error) {
	if !a.Sandbox {
		return nil, ap2.ErrLiveRefused
	}
	if len(a.JWKS) > 0 {
		return parseKeys(a.JWKS)
	}
	if err := CheckURL(src); err != nil {
		if errors.Is(err, ap2.ErrLiveRefused) {
			return nil, err
		}
		return nil, nil
	}
	ck := a.ID.String() + " " + src
	now := s.clock.Now()
	s.mu.Lock()
	e := s.cache[ck]
	if e != nil && now.Sub(e.at) < CacheFor {
		has := slices.ContainsFunc(e.keys, func(k key) bool { return k.kid == kid || k.thumbprint == kid })
		if has || now.Sub(e.miss) < MissInterval {
			out := e.keys
			s.mu.Unlock()
			return out, nil
		}
		e.miss = now
	}
	s.mu.Unlock()
	ks, err := s.fetch(ctx, src)
	if err != nil {
		s.log.WarnContext(ctx, "payments.anchor_keys_unavailable", slog.String("anchor_id", a.ID.String()), pclog.Err(err))
		return nil, nil
	}
	s.mu.Lock()
	s.cache[ck] = &entry{keys: ks, at: now, miss: now}
	s.mu.Unlock()
	return ks, nil
}

func (s *KeySource) fetch(ctx context.Context, src string) ([]key, error) {
	u, err := url.Parse(src)
	if err != nil {
		return nil, err
	}
	client := s.public
	if isLoopbackHost(u.Hostname()) {
		client = s.local
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/http-message-signatures-directory+json, application/jwk-set+json, application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anchors: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anchors: fetch: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocument+1))
	if err != nil || len(b) > MaxDocument {
		return nil, errors.New("anchors: fetch: document too large or unreadable")
	}
	return parseKeys(b)
}

// parseKeys keeps the usable keys of a JWKS, or of a single JWK (a key
// service answer): ES256 P-256 or Ed25519 public keys, at most MaxKeys.
// Every other key is skipped; none usable is an error.
func parseKeys(raw []byte) ([]key, error) {
	if len(raw) > MaxDocument {
		return nil, errors.New("anchors: key document too large")
	}
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("anchors: key document: %w", err)
	}
	members := set.Keys
	if members == nil {
		members = []jsontext.Value{raw}
	}
	var out []key
	for _, m := range members {
		if len(out) == MaxKeys {
			break
		}
		pub, kid, err := sdjwt.PublicKey(m)
		if err != nil {
			continue
		}
		var jk jose.JSONWebKey
		if jk.UnmarshalJSON(m) != nil || (jk.Use != "" && jk.Use != "sig") {
			continue
		}
		tp, err := jk.Thumbprint(crypto.SHA256)
		if err != nil {
			continue
		}
		out = append(out, key{kid: kid, thumbprint: b64url(tp), pub: pub})
	}
	if len(out) == 0 {
		return nil, errors.New("anchors: no usable keys")
	}
	return out, nil
}
