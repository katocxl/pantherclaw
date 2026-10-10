// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package keydocs serves the evidence key documents (PAP-1 §11, G0 M7
// design decisions 13 and 17, HR-194):
//
//   - /.well-known/pantherclaw/evidence-keys.json lists every key that signs
//     receipts, checkpoints (Ed25519 and the optional ML-DSA-65
//     co-signature), anchors and evidence-pack manifests, revoked ones
//     included, each with its validity and state, in the trust file's key
//     shape (pantherclaw.trust/v1): `pclaw evidence trust` pins it as it is;
//   - /.well-known/pantherclaw/revoked-keys.json lists every revoked key of a
//     published purpose (the JWKS purposes and the evidence purposes).
//
// A key is valid from its creation, rounded down to the second, until it
// stopped signing: when it became RETIRING or REVOKED, rounded up. An active
// key has no end. Both documents are public and carry no private material.
package keydocs

import (
	"context"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Paths of the documents.
const (
	EvidenceKeysPath = "/.well-known/pantherclaw/evidence-keys.json"
	RevokedKeysPath  = "/.well-known/pantherclaw/revoked-keys.json"
)

// RevokedKeysFormat is the format of revoked-keys.json.
const RevokedKeysFormat = "pantherclaw.revoked-keys/v1"

// cacheTTL bounds how often a public request reaches the database.
const cacheTTL = time.Minute

// Lister lists the published keys of purposes (keystore.PublishedKeys).
type Lister func(ctx context.Context, purposes []keys.Purpose) ([]keystore.PublishedKey, error)

// revocationPurposes are the purposes whose keys anyone may have pinned.
func revocationPurposes() []keys.Purpose {
	out := keys.JWKSPurposes()
	for _, p := range keys.EvidencePurposes() {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func notBefore(k keystore.PublishedKey) time.Time { return k.Created.UTC().Truncate(time.Second) }

// notAfter is when a key stopped signing, rounded up to the second; zero
// for an active key.
func notAfter(k keystore.PublishedKey) time.Time {
	if k.State == keys.StateActive {
		return time.Time{}
	}
	t := k.Changed.UTC()
	if r := t.Truncate(time.Second); !r.Equal(t) {
		return r.Add(time.Second)
	}
	return t
}

// EvidenceKeys encodes evidence-keys.json for the keys ks; it lists only
// the evidence purposes.
func EvidenceKeys(issuer, logOrigin string, ks []keystore.PublishedKey) ([]byte, error) {
	doc := bundle.Trust{Format: bundle.EvidenceKeysFormat, Issuer: issuer, LogOrigin: logOrigin, Keys: []bundle.TrustedKey{}}
	for _, k := range ks {
		if !slices.Contains(keys.EvidencePurposes(), k.Purpose) {
			continue
		}
		doc.Keys = append(doc.Keys, bundle.TrustedKey{
			KID: k.KID, Purpose: string(k.Purpose), Algorithm: string(k.Algorithm), PublicKey: k.Public,
			NotBefore: notBefore(k), NotAfter: notAfter(k), State: string(k.State),
		})
	}
	return json.Marshal(doc)
}

type revokedKey struct {
	KID       string    `json:"kid"`
	Purpose   string    `json:"purpose"`
	Algorithm string    `json:"algorithm"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevokedKeys encodes revoked-keys.json for the revoked keys among ks.
func RevokedKeys(issuer string, ks []keystore.PublishedKey) ([]byte, error) {
	doc := struct {
		Format string       `json:"format"`
		Issuer string       `json:"issuer,omitzero"`
		Keys   []revokedKey `json:"keys"`
	}{Format: RevokedKeysFormat, Issuer: issuer, Keys: []revokedKey{}}
	purposes := revocationPurposes()
	for _, k := range ks {
		if k.State == keys.StateRevoked && slices.Contains(purposes, k.Purpose) {
			doc.Keys = append(doc.Keys, revokedKey{
				KID: k.KID, Purpose: string(k.Purpose), Algorithm: string(k.Algorithm), RevokedAt: notAfter(k),
			})
		}
	}
	return json.Marshal(doc)
}

type cached struct {
	body []byte
	at   time.Time
}

// Handler serves both documents from a short cache.
type Handler struct {
	list              Lister
	issuer, logOrigin string
	clock             clock.Clock
	log               *slog.Logger

	mu    sync.Mutex
	cache map[string]cached
}

// New returns the handler. issuer is the deployment's public URL.
func New(list Lister, issuer, logOrigin string, clk clock.Clock, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{list: list, issuer: issuer, logOrigin: logOrigin, clock: clk, log: log, cache: map[string]cached{}}
}

// Mount adds the documents to mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET "+EvidenceKeysPath, h.serve(EvidenceKeysPath, keys.EvidencePurposes(), func(ks []keystore.PublishedKey) ([]byte, error) {
		return EvidenceKeys(h.issuer, h.logOrigin, ks)
	}))
	mux.HandleFunc("GET "+RevokedKeysPath, h.serve(RevokedKeysPath, revocationPurposes(), func(ks []keystore.PublishedKey) ([]byte, error) {
		return RevokedKeys(h.issuer, ks)
	}))
}

func (h *Handler) serve(path string, purposes []keys.Purpose, encode func([]keystore.PublishedKey) ([]byte, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := h.document(r.Context(), path, purposes, encode)
		if err != nil {
			h.log.WarnContext(r.Context(), "keydocs.unavailable", slog.String("path", path), pclog.Err(err))
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	}
}

func (h *Handler) document(ctx context.Context, path string, purposes []keys.Purpose,
	encode func([]keystore.PublishedKey) ([]byte, error),
) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.clock.Now()
	if c, ok := h.cache[path]; ok && now.Sub(c.at) < cacheTTL {
		return c.body, nil
	}
	ks, err := h.list(ctx, purposes)
	if err != nil {
		return nil, err
	}
	body, err := encode(ks)
	if err != nil {
		return nil, err
	}
	h.cache[path] = cached{body: body, at: now}
	return body, nil
}
