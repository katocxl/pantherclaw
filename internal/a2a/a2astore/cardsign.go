// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2astore

import (
	"bytes"
	"context"
	"crypto"
	"errors"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Refusals of SignCard.
var (
	// ErrCardNotOurs refuses a connection that is not the calling gateway's
	// a2a connection, or that has no serving pin.
	ErrCardNotOurs = pcerr.New(pcerr.NotFound, "A2A_CARD_NOT_FOUND", "no a2a connection of this gateway serves a card")
	// ErrCardMismatch refuses a card that is not the connection's pinned card
	// rewritten for the gateway: the key signs only what the server would
	// rewrite itself.
	ErrCardMismatch = pcerr.New(pcerr.InvalidArgument, "A2A_CARD_MISMATCH", "the card is not this connection's pinned card")
	// ErrCardDrifted refuses a pin whose card changed at the peer.
	ErrCardDrifted = pcerr.New(pcerr.FailedPrecondition, "A2A_CARD_DRIFTED", "the pinned card has drifted")
	// ErrCardNoPublicURL: no person stated where this connection's card is
	// served, so the server signs nothing and the card stays unsigned (G0 M24
	// D247).
	ErrCardNoPublicURL = pcerr.New(pcerr.FailedPrecondition, "A2A_CARD_NO_PUBLIC_URL", "this connection has no public URL to sign a card for")
)

// CardSigner signs the rewritten cards gateways serve with the platform's
// a2a_card key, published in the JWKS (G0 M24 D232).
type CardSigner struct {
	Pool *db.Pool
	Keys *keys.Registry
}

// SignCard returns card with the platform's signature and the JWKS that
// verifies it. A gateway presents the card it rewrote; the server rewrites
// the connection's active pin itself for the public URL a person stored on
// that pin and signs only an exact match, so a compromised gateway chooses
// nothing, not even its host (D247).
func (s *CardSigner) SignCard(ctx context.Context, org ids.OrgID, gateway, conn ids.UUID, card []byte) (signed, jwks []byte, err error) {
	c, err := wire.ParseCard(card)
	if err != nil || len(c.SupportedInterfaces) != 1 {
		return nil, nil, ErrCardMismatch
	}
	url := c.SupportedInterfaces[0].URL
	var want []byte
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		w, err := q.GetA2AConnectionWriter(ctx, org, conn)
		if db.IsNoRows(err) || (err == nil && w.GatewayID != gateway) {
			return ErrCardNotOurs
		} else if err != nil {
			return err
		}
		pin, err := Get(ctx, q, org, conn, StateActive)
		if errors.Is(err, ErrNotFound) {
			return ErrCardNotOurs
		} else if err != nil {
			return err
		}
		if pin.DriftedAt != nil {
			return ErrCardDrifted
		}
		cfg := pin.Config
		if cfg.GetPublicUrl() == "" {
			return ErrCardNoPublicURL
		}
		if url != cfg.GetPublicUrl() {
			return ErrCardMismatch
		}
		want, err = wire.Rewrite(cfg.GetPinnedCard(), cfg.GetInterface().GetProtocol(), url, cfg.GetSkills())
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(want, card) {
		return nil, nil, ErrCardMismatch
	}
	ks := s.Keys.Keys(keys.PurposeA2ACard)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return nil, nil, keys.ErrNoActiveKey
	}
	k := ks[0]
	if signed, err = wire.Sign(card, k.KID, k.Private.Reveal()); err != nil {
		return nil, nil, err
	}
	if jwks, err = wire.PublicJWKS(map[string]crypto.PublicKey{k.KID: k.Public}); err != nil {
		return nil, nil, err
	}
	return signed, jwks, nil
}
