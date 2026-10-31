// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	// signedCardTTL is how long a signed card is served from the cache (G0
	// M24 D232).
	signedCardTTL = time.Hour
	// signFailureTTL is how long a card that failed to sign is served
	// unsigned before the gateway asks again (G0 M24 D253).
	signFailureTTL = time.Minute
	// maxSignedCards bounds the cache.
	maxSignedCards = 1024
	// signCardTimeout bounds the call that signs: a slow server costs a
	// waiting agent this much, and then it gets the card unsigned.
	signCardTimeout = 3 * time.Second
)

// SignCard asks the server to sign a rewritten card, and returns the signed
// card with the JWKS that verifies it.
type SignCard func(ctx context.Context, conn string, card []byte) (signed, jwks []byte, err error)

// signedCard is one cached card.
type signedCard struct {
	card    []byte
	expires time.Time
}

// signedCards caches signed cards by the digest of the rewritten card.
type signedCards struct {
	mu   sync.Mutex
	byID map[[32]byte]signedCard
	// failed holds when each failed card may be tried again.
	failed map[[32]byte]time.Time
}

// failing reports whether card id failed to sign within signFailureTTL.
func (s *signedCards) failing(id [32]byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.failed[id]
	if ok && !now.Before(until) {
		delete(s.failed, id)
		return false
	}
	return ok
}

func (s *signedCards) fail(id [32]byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == nil || len(s.failed) >= maxSignedCards {
		s.failed = map[[32]byte]time.Time{}
	}
	s.failed[id] = now.Add(signFailureTTL)
}

func (s *signedCards) get(id [32]byte, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byID[id]
	if !ok || !now.Before(c.expires) {
		delete(s.byID, id)
		return nil, false
	}
	return c.card, true
}

func (s *signedCards) put(id [32]byte, card []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byID == nil || len(s.byID) >= maxSignedCards {
		s.byID = map[[32]byte]signedCard{}
	}
	s.byID[id] = signedCard{card: card, expires: now.Add(signedCardTTL)}
}

// WithCardSigner has the face serve cards the server signed (D232).
func (h *Handler) WithCardSigner(sign SignCard) *Handler {
	h.signCard = sign
	return h
}

// checkSigned is the gateway's own proof that what the server answered is
// what it asked for, signed: the card without its signatures is the card it
// sent, and the signature verifies under the answered key (HR-590).
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
		return errors.New("a2a: the signed card is another card")
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

// signed returns card with the server's signature, from the cache when it
// can. Whatever goes wrong, it logs that and returns card as rewritten, with
// no signature: never a signature that does not verify (HR-590). A failure
// holds for signFailureTTL, so a card nobody can sign does not cost every
// reader the call (D253); a reader that hung up says nothing about the card.
func (h *Handler) signed(ctx context.Context, conn string, card []byte) []byte {
	if h.signCard == nil {
		return card
	}
	id := sha256.Sum256(card)
	if c, ok := h.cards.get(id, h.now()); ok {
		return c
	}
	if h.cards.failing(id, h.now()) {
		return card
	}
	sctx, cancel := context.WithTimeout(ctx, signCardTimeout)
	defer cancel()
	signed, jwks, err := h.signCard(sctx, conn, card)
	if err == nil {
		err = checkSigned(card, signed, jwks)
	}
	if err != nil {
		h.log.WarnContext(ctx, "gateway.a2a_card_unsigned", pclog.Err(err))
		if ctx.Err() == nil {
			h.cards.fail(id, h.now())
		}
		return card
	}
	h.cards.put(id, signed, h.now())
	return signed
}
