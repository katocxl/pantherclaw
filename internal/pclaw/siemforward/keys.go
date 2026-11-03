// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siemforward

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// maxJWKS bounds a JWKS document, fetched or read.
const maxJWKS = 64 << 10

// ParseSecret reads a destination's signing secret as PantherClaw shows it
// (`whsec_` and base64). Its error never contains the value.
func ParseSecret(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), ndomain.SecretPrefix)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("not a signing secret (whsec_ followed by base64)")
	}
	return b, nil
}

// Keys are the Ed25519 public keys of the org's webhook JWKS
// (`/.well-known/pantherclaw/orgs/{org}/webhook-jwks.json`).
type Keys interface {
	// Current returns the keys known now.
	Current() []ed25519.PublicKey
	// Refresh reloads the keys when the source may, and reports whether it
	// did. A file never reloads; a URL at most once a minute.
	Refresh(ctx context.Context) bool
}

// ParseJWKS returns the webhooks keys of a JWKS document: Ed25519 keys
// whose kid is the webhooks kid of the key itself. Other keys are skipped.
func ParseJWKS(doc []byte) ([]ed25519.PublicKey, error) {
	if len(doc) > maxJWKS {
		return nil, errors.New("the JWKS is larger than 64 KiB")
	}
	var set struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, errors.New("not a JWKS document")
	}
	out := make([]ed25519.PublicKey, 0, len(set.Keys))
	for _, k := range set.Keys {
		pub, err := k.Key()
		if err != nil || k.Kid != keys.KIDFor(keys.PurposeWebhooks, pub) {
			continue
		}
		out = append(out, pub)
	}
	return out, nil
}

// StaticKeys are keys read once, from `--jwks-file`.
type StaticKeys []ed25519.PublicKey

// Current returns the keys.
func (k StaticKeys) Current() []ed25519.PublicKey { return k }

// Refresh never reloads.
func (StaticKeys) Refresh(context.Context) bool { return false }

// JWKSURL holds the keys fetched from `--jwks-url` and refetches them, at
// most once a minute, when a signature names a key it does not know: the
// `v1a,` signature carries no kid, so a signature no known key verifies is
// treated as an unknown kid (for example after the org rotated its key).
type JWKSURL struct {
	url    string
	client *http.Client
	now    func() time.Time
	log    *slog.Logger

	fetch   sync.Mutex // one fetch at a time
	mu      sync.RWMutex
	keys    []ed25519.PublicKey
	fetched time.Time // the last attempt, successful or not
}

// CheckJWKSURL accepts an https URL with a host and nothing secret in it.
func CheckJWKSURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return errors.New("--jwks-url is not a URL")
	case u.Scheme != "https" || u.Host == "" || u.Hostname() == "":
		return errors.New("--jwks-url must be an https URL")
	case u.User != nil || u.Fragment != "":
		return errors.New("--jwks-url takes no credentials or fragment")
	}
	return nil
}

// NewJWKSURL fetches the JWKS once and returns the source. client never
// follows redirects (pclaw's control-plane client).
func NewJWKSURL(ctx context.Context, raw string, client *http.Client, now func() time.Time, log *slog.Logger) (*JWKSURL, error) {
	if err := CheckJWKSURL(raw); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = pclog.Discard()
	}
	j := &JWKSURL{url: raw, client: client, now: now, log: log}
	ks, err := j.get(ctx)
	if err != nil {
		return nil, err
	}
	j.keys, j.fetched = ks, now()
	return j, nil
}

// Current returns the keys of the last successful fetch.
func (j *JWKSURL) Current() []ed25519.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keys
}

// Refresh refetches the JWKS unless it was tried less than a minute ago. A
// failed fetch keeps the keys it had.
func (j *JWKSURL) Refresh(ctx context.Context) bool {
	j.fetch.Lock()
	defer j.fetch.Unlock()
	j.mu.RLock()
	recent := j.now().Sub(j.fetched) < JWKSRefetchEvery
	j.mu.RUnlock()
	if recent {
		return false
	}
	ks, err := j.get(ctx)
	j.mu.Lock()
	defer j.mu.Unlock()
	j.fetched = j.now()
	if err != nil {
		j.log.WarnContext(ctx, "siem.forward.jwks_refetch_failed", pclog.Err(err))
		return false
	}
	j.keys = ks
	return true
}

func (j *JWKSURL) get(ctx context.Context) ([]ed25519.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch the JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch the JWKS: status %d", resp.StatusCode)
	}
	doc, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS+1))
	if err != nil {
		return nil, fmt.Errorf("read the JWKS: %w", err)
	}
	return ParseJWKS(doc)
}
