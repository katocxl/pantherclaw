// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Signature scheme errors (G0 M20 D251).
var (
	ErrInvalidScheme      = pcerr.New(pcerr.InvalidArgument, "INVALID_SIGNATURE_SCHEME", "the signature scheme must be hmac or hmac+ed25519")
	ErrSigningUnavailable = pcerr.New(pcerr.FailedPrecondition, "WEBHOOK_SIGNING_UNAVAILABLE", "Ed25519 webhook signing is not available on this server")
)

// SetChannelSignatureScheme opts a webhook channel in to Ed25519
// signatures (hmac+ed25519) or back to HMAC only (hmac), audited
// (notification.manage). HMAC is sent either way (HR-510). Opting in makes
// sure the org has its webhooks key, so the org's JWKS lists it before the
// first signed delivery. It returns the org's webhook JWKS URL.
func (s *Service) SetChannelSignatureScheme(ctx context.Context, id ids.UUID, scheme string) (ChannelView, string, error) {
	sc := domain.SignatureScheme(scheme)
	if !sc.Valid() {
		return ChannelView{}, "", ErrInvalidScheme
	}
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return ChannelView{}, "", err
	}
	if err := c.Require(td.PermNotificationManage, td.OrgPath(c.Org)); err != nil {
		return ChannelView{}, "", err
	}
	kid := ""
	if sc.Ed25519() {
		if s.webhookKeys == nil {
			return ChannelView{}, "", ErrSigningUnavailable
		}
		if kid, err = s.webhookKeys.EnsureWebhookKey(ctx, c.Org); err != nil {
			return ChannelView{}, "", err
		}
	}
	var out ChannelView
	err = s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		prev, err := q.SetChannelSignatureScheme(ctx, scheme, c.Org, id)
		if db.IsNoRows(err) {
			// A missing, deleted or non-webhook channel: only webhook
			// channels sign Standard Webhooks.
			ch, gerr := q.GetChannel(ctx, c.Org, id)
			if gerr != nil {
				return notFoundAs(gerr, ErrChannelNotFound)
			}
			if domain.Kind(ch.Kind) != domain.KindWebhook {
				return ErrNotAWebhook
			}
			return ErrChannelNotFound
		} else if err != nil {
			return err
		}
		details := map[string]string{"scheme": scheme, "previous": prev}
		if kid != "" {
			details["kid"] = kid
		}
		if err := s.audit(ctx, tx, c, "notification.channel_signature_scheme_set", id, details); err != nil {
			return err
		}
		ch, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		out = channelView(ch)
		return nil
	})
	if err != nil {
		return ChannelView{}, "", err
	}
	return out, domain.WebhookJWKSURL(s.cfg.PublicURL, c.Org), nil
}
