// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package fedface

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	// cardTTL is the longest a signed listing card is served from the
	// cache (D1024).
	cardTTL = time.Hour
	// maxCards bounds the cache.
	maxCards = 1024
	// signTimeout bounds the call that fetches a signed card.
	signTimeout = 3 * time.Second
)

// SignedCard is a listing's card as the server rewrote and signed it with
// our org's federation key (FederationService.SignListingCard).
type SignedCard struct {
	Card []byte
	// Expires is when the server says to stop serving it.
	Expires time.Time
}

// SignListingCard asks the server for a listing's signed card.
type SignListingCard func(ctx context.Context, listing string) (SignedCard, error)

// cardCache caches signed cards by listing.
type cardCache struct {
	mu     sync.Mutex
	byName map[string]SignedCard
}

func (s *cardCache) get(listing string, now time.Time) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.byName[listing]
	if !ok || !now.Before(c.Expires) {
		delete(s.byName, listing)
		return nil, false
	}
	return c.Card, true
}

func (s *cardCache) put(listing string, c SignedCard, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byName == nil || len(s.byName) >= maxCards {
		s.byName = map[string]SignedCard{}
	}
	if limit := now.Add(cardTTL); c.Expires.IsZero() || c.Expires.After(limit) {
		c.Expires = limit
	}
	s.byName[listing] = c
}

// card serves the listing's signed card. Unlike the agent-facing A2A face,
// it is never served unsigned: a peer accepts only a card our federation
// key signed (D1022), so a card that cannot be had signed is not served.
func (h *Handler) card(ctx context.Context, w http.ResponseWriter, r *http.Request, listing string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.fail(w, nil, &faceError{status: http.StatusMethodNotAllowed, rpc: wire.CodeInvalidRequest, reason: CodeBadRequest, message: "the agent card is read with GET"})
		return
	}
	signed, err := h.signed(ctx, listing)
	switch {
	case connect.CodeOf(err) == connect.CodeNotFound:
		h.fail(w, nil, &faceError{status: http.StatusNotFound, rpc: wire.CodeInvalidRequest, reason: CodeListingUnknown, message: "unknown listing"})
		return
	case err != nil:
		h.fail(w, nil, &faceError{status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: CodeUnavailable, message: "the listing's card cannot be served now"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(signed) //nolint:gosec // G705: the server-signed card, not request input
}

// signed returns the listing's signed card, from the cache when it can.
func (h *Handler) signed(ctx context.Context, listing string) ([]byte, error) {
	if h.sign == nil {
		return nil, errNoSigner
	}
	if c, ok := h.cards.get(listing, h.now()); ok {
		return c, nil
	}
	sctx, cancel := context.WithTimeout(ctx, signTimeout)
	defer cancel()
	c, err := h.sign(sctx, listing)
	if _, perr := wire.ParseCard(c.Card); err == nil && perr != nil {
		err = errCardInvalid
	}
	if err != nil {
		h.log.WarnContext(ctx, "gateway.federation_card_unavailable", pclog.Err(err))
		return nil, err
	}
	h.cards.put(listing, c, h.now())
	return c.Card, nil
}

// errNoSigner: the gateway was built without the server's card signer.
var errNoSigner = errors.New("fedface: no listing card signer")
