// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package fedface

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"sync"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	// cardTTL is how long a signed listing card is served from the cache
	// (D1024).
	cardTTL = time.Hour
	// maxCards bounds the cache.
	maxCards = 1024
	// signTimeout bounds the call that signs a card.
	signTimeout = 3 * time.Second
)

// cachedCard is one signed card.
type cachedCard struct {
	card    []byte
	expires time.Time
}

// cardCache caches signed cards by listing and the digest of the rewritten
// card, so a changed card or skill list is signed again.
type cardCache struct {
	mu   sync.Mutex
	byID map[[32]byte]cachedCard
}

func cardKey(listing string, card []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(listing))
	h.Write([]byte{0})
	h.Write(card)
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k
}

func (s *cardCache) get(id [32]byte, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok || !now.Before(c.expires) {
		delete(s.byID, id)
		return nil, false
	}
	return c.card, true
}

func (s *cardCache) put(id [32]byte, card []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil || len(s.byID) >= maxCards {
		s.byID = map[[32]byte]cachedCard{}
	}
	s.byID[id] = cachedCard{card: card, expires: now.Add(cardTTL)}
}

// rewrite is the listing's card as a peer sees it: one interface, this
// face's JSON-RPC endpoint, and the listing's skills only.
func (h *Handler) rewrite(l Listing) ([]byte, bool) {
	if h.peerCard == nil {
		return nil, false
	}
	card, _, ok := h.peerCard(l.Connection)
	if !ok {
		return nil, false
	}
	out, err := wire.Rewrite(card, wire.BindingJSONRPC, h.URL(l.Name), l.Skills)
	if err != nil {
		return nil, false
	}
	return out, true
}

// card serves the listing's signed card. Unlike the agent-facing A2A face,
// it is never served unsigned: a peer accepts only a card our federation
// key signed (D1022), so a card that cannot be signed is not served.
func (h *Handler) card(ctx context.Context, w http.ResponseWriter, r *http.Request, l Listing) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.fail(w, nil, &faceError{status: http.StatusMethodNotAllowed, rpc: wire.CodeInvalidRequest, reason: CodeBadRequest, message: "the agent card is read with GET"})
		return
	}
	out, ok := h.rewrite(l)
	if !ok {
		h.fail(w, nil, &faceError{status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: CodeUnavailable, message: "the listing's card cannot be served now"})
		return
	}
	signed, ok := h.signed(ctx, l.Name, out)
	if !ok {
		h.fail(w, nil, &faceError{status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: CodeUnavailable, message: "the listing's card cannot be served now"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(signed)
}

// signed returns card signed by our org's federation key, from the cache
// when it can. The gateway checks the server's answer is the card it sent
// and that the signature verifies under the answered keys (HR-590).
func (h *Handler) signed(ctx context.Context, listing string, card []byte) ([]byte, bool) {
	if h.sign == nil {
		return nil, false
	}
	id := cardKey(listing, card)
	if c, ok := h.cards.get(id, h.now()); ok {
		return c, true
	}
	sctx, cancel := context.WithTimeout(ctx, signTimeout)
	defer cancel()
	signed, jwks, err := h.sign(sctx, listing, card)
	if err == nil {
		err = checkSigned(card, signed, jwks)
	}
	if err != nil {
		h.log.WarnContext(ctx, "gateway.federation_card_unsigned", pclog.Err(err))
		return nil, false
	}
	h.cards.put(id, signed, h.now())
	return signed, true
}

// checkSigned is the gateway's own proof that what the server answered is
// what it asked for, signed: the card without its signatures is the card it
// sent, and the signature verifies under the answered keys (HR-590).
func checkSigned(card, signed, jwks []byte) error {
	sent, err := wire.SigningPayload(card)
	if err != nil {
		return err
	}
	got, err := wire.SigningPayload(signed)
	if err != nil {
		return err
	}
	if !bytes.Equal(sent, got) {
		return errors.New("fedface: the signed card is another card")
	}
	keys, err := wire.ParseKeys(jwks)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return wire.ErrCardKeysRequired
	}
	return wire.VerifySignatures(signed, keys)
}
