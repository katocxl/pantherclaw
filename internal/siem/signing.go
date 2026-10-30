// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siem

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Signature scheme errors (G0 M20 D251).
var (
	ErrInvalidScheme      = pcerr.New(pcerr.InvalidArgument, "INVALID_SIGNATURE_SCHEME", "the signature scheme must be hmac or hmac+ed25519")
	ErrSigningUnavailable = pcerr.New(pcerr.FailedPrecondition, "WEBHOOK_SIGNING_UNAVAILABLE", "Ed25519 webhook signing is not available on this server")
)

// WithWebhookKeys sets the signer of the `v1a,` signature that opted-in
// destinations receive next to HMAC (G0 M20 D251, HR-510).
func (s *Service) WithWebhookKeys(k ndomain.WebhookKeys) *Service {
	s.webhookKeys = k
	return s
}

// SetSignatureScheme opts a destination in to Ed25519 signatures
// (hmac+ed25519) or back to HMAC only (hmac), audited (siem.manage, a
// person, Business). HMAC is sent either way (HR-510). Opting in makes
// sure the org has its webhooks key, so the org's JWKS lists it before the
// first signed batch. It
// returns the org's webhook JWKS URL.
func (s *Service) SetSignatureScheme(ctx context.Context, id ids.UUID, scheme string) (Destination, string, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Destination{}, "", err
	}
	sc := ndomain.SignatureScheme(scheme)
	if !sc.Valid() {
		return Destination{}, "", ErrInvalidScheme
	}
	kid := ""
	if sc.Ed25519() {
		if s.webhookKeys == nil {
			return Destination{}, "", ErrSigningUnavailable
		}
		if kid, err = s.webhookKeys.EnsureWebhookKey(ctx, c.Org); err != nil {
			return Destination{}, "", err
		}
	}
	var out Destination
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		prev, err := q.SetSIEMDestinationSignatureScheme(ctx, scheme, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		details := map[string]string{"scheme": scheme, "previous": prev}
		if kid != "" {
			details["kid"] = kid
		}
		if err := s.audit(ctx, tx, c, "siem.destination_signature_scheme_set", id, details); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return Destination{}, "", err
	}
	return out, ndomain.WebhookJWKSURL(s.cfg.PublicURL, c.Org), nil
}
