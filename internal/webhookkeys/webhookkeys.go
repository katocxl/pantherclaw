// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package webhookkeys serves the organization's Ed25519 webhook signing
// key (G0 M20 D251, D261; HR-510..512): listing its ACTIVE and RETIRING
// keys, and rotating it with a step-up.
package webhookkeys

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/keystore"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// StepUpWithin is how fresh the rotating person's step-up must be.
const StepUpWithin = 5 * time.Minute

// API errors.
var (
	ErrStepUp = pcerr.New(pcerr.PermissionDenied, "STEP_UP_REQUIRED",
		"verify with one of your security keys on this page first")
	ErrRotating = pcerr.New(pcerr.FailedPrecondition, "WEBHOOK_KEY_ROTATING",
		"the previous webhook key is still retiring; rotate again after its 24-hour overlap")
)

// Service lists and rotates the caller's org's webhook key.
type Service struct {
	pool      *db.Pool
	keys      *keystore.WebhookKeys
	publicURL string
}

// New returns the service.
func New(pool *db.Pool, keys *keystore.WebhookKeys, publicURL string) *Service {
	return &Service{pool: pool, keys: keys, publicURL: publicURL}
}

// List returns the org's ACTIVE key and its RETIRING key during the
// overlap, and the org's JWKS URL (webhook_key.read).
func (s *Service) List(ctx context.Context) ([]keystore.WebhookKey, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	if err := c.Require(td.PermWebhookKeyRead, td.OrgPath(c.Org)); err != nil {
		return nil, "", err
	}
	ks, err := s.keys.ListWebhookKeys(ctx, c.Org)
	if err != nil {
		return nil, "", err
	}
	return ks, ndomain.WebhookJWKSURL(s.publicURL, c.Org), nil
}

// Rotate gives the org a new ACTIVE webhook key; the old one is RETIRING
// for the 24-hour overlap (HR-512). It needs webhook_key.manage and a
// person whose browser session stepped up within StepUpWithin with one of
// their own active security keys; it is refused while a RETIRING key is
// still in its overlap (D261). The keystore audits the retirement and the
// new key; the rotation itself is audited with the step-up's key.
func (s *Service) Rotate(ctx context.Context) (keystore.WebhookKey, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return keystore.WebhookKey{}, "", err
	}
	if err := c.Require(td.PermWebhookKeyManage, td.OrgPath(c.Org)); err != nil {
		return keystore.WebhookKey{}, "", err
	}
	if !c.Human() || c.Credential != tenancy.CredBrowserSession || c.Session.IsZero() {
		return keystore.WebhookKey{}, "", ErrStepUp
	}
	newKID, retiring, err := s.keys.RotateWebhookKey(ctx, c.Org, c.Actor(), func(ctx context.Context, tx db.TenantTx, newKID, retiring string) error {
		su, err := dbq.New(tx).SessionStepUp(ctx, c.Org, c.Session, c.Principal.ID)
		if db.IsNoRows(err) {
			return ErrStepUp
		} else if err != nil {
			return err
		}
		if su.DbNow.Sub(su.StepUpAt) > StepUpWithin || su.StepUpAt.After(su.DbNow.Add(time.Minute)) {
			return ErrStepUp
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "webhook_key.rotated", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "signing_key", ID: newKID},
			Details: map[string]string{"retiring_kid": retiring, "security_key": su.CredentialID.String()},
		})
		return err
	})
	if errors.Is(err, keystore.ErrWebhookKeyRotating) {
		return keystore.WebhookKey{}, "", ErrRotating
	} else if err != nil {
		return keystore.WebhookKey{}, "", err
	}
	ks, err := s.keys.ListWebhookKeys(ctx, c.Org)
	if err != nil {
		return keystore.WebhookKey{}, "", err
	}
	for _, k := range ks {
		if k.KID == newKID {
			return k, retiring, nil
		}
	}
	return keystore.WebhookKey{}, retiring, keystore.ErrNoWebhookKey
}
