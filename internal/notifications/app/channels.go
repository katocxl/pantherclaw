// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Encrypted channel columns: the AAD binds org, table, column and row, so
// a secret copied to another channel or column does not decrypt (HR-062).
const (
	channelsTable    = "notification_channels"
	secretColumn     = "secret"
	prevSecretColumn = "prev_secret"
)

// ErrChannelExists reports a live channel with the same name.
var ErrChannelExists = errors.New("notifications: a channel with this name exists")

// NewChannel describes a channel to create. For a Slack channel URL is the
// incoming-webhook URL, which is a secret: it is stored encrypted and never
// returned.
type NewChannel struct {
	Org           ids.OrgID
	Name          string
	Kind          domain.Kind
	EventTypes    []string
	MinSeverity   domain.Severity
	RecipientRole string
	URL           string
	CreatedBy     string
}

// CreatedChannel is a new channel. Secret is the webhook signing secret,
// shown once ("" for other kinds).
type CreatedChannel struct {
	ID     ids.UUID
	Secret string
}

// CreateChannelTx validates and stores a channel in tx (HR-157). Callers
// check authorization and edition limits.
func (s *Service) CreateChannelTx(ctx context.Context, tx db.TenantTx, in NewChannel) (CreatedChannel, error) {
	if in.MinSeverity == "" {
		in.MinSeverity = domain.Info
	}
	if !domain.ValidChannelName(in.Name) || !in.Kind.Valid() || !in.MinSeverity.Valid() || in.CreatedBy == "" {
		return CreatedChannel{}, domain.ErrInvalid
	}
	if err := domain.ValidEventTypes(in.EventTypes); err != nil {
		return CreatedChannel{}, err
	}
	// Fields that do not belong to the kind are refused, not ignored.
	if (in.Kind != domain.KindEmail && in.RecipientRole != "") || (!in.Kind.HasSecret() && in.URL != "") {
		return CreatedChannel{}, domain.ErrInvalid
	}
	out := CreatedChannel{ID: ids.NewV7()}
	p := dbq.InsertChannelParams{
		OrgID: in.Org, ID: out.ID, Name: in.Name, Kind: string(in.Kind), EventTypes: in.EventTypes,
		MinSeverity: string(in.MinSeverity), CreatedBy: in.CreatedBy,
	}
	var plain []byte
	switch in.Kind {
	case domain.KindEmail:
		if _, ok := td.LookupRole(td.RoleName(in.RecipientRole)); !ok {
			return CreatedChannel{}, domain.ErrInvalid
		}
		p.RecipientRole = &in.RecipientRole
	case domain.KindWebhook:
		if err := domain.CheckWebhookURL(in.URL, s.ownHost, s.deniedHost); err != nil {
			return CreatedChannel{}, err
		}
		secret, err := domain.NewSigningSecret()
		if err != nil {
			return CreatedChannel{}, err
		}
		p.Url, plain, out.Secret = &in.URL, secret, domain.FormatSecret(secret)
	case domain.KindSlack:
		if err := domain.CheckSlackURL(in.URL); err != nil {
			return CreatedChannel{}, err
		}
		plain = []byte(in.URL)
	case domain.KindLog:
		// nothing to store beyond the subscription
	}
	if plain != nil {
		blob, err := s.envelope.Encrypt(ctx, s.field(in.Org, out.ID, secretColumn), SecretPurpose, plain)
		if err != nil {
			return CreatedChannel{}, fmt.Errorf("notifications: encrypt channel secret: %w", err)
		}
		p.Secret = blob
	}
	err := dbq.New(tx).InsertChannel(ctx, p)
	if db.IsUniqueViolation(err) {
		return CreatedChannel{}, ErrChannelExists
	}
	return out, err
}

func (s *Service) field(org ids.OrgID, id ids.UUID, column string) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: channelsTable, Column: column, RowID: id.String()}
}
