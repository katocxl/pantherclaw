// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Channel administration limits.
const (
	// CommunityChannelLimit is the number of channels Community allows
	// (founder decision 3, G0 M5); other editions are unlimited.
	CommunityChannelLimit = 3
	// SecretOverlap is how long a rotated signing secret keeps signing.
	SecretOverlap = 24 * time.Hour
	// recentDeliveries is how many deliveries GetChannel shows.
	recentDeliveries = 20
)

// API errors.
var (
	ErrChannelNotFound  = pcerr.New(pcerr.NotFound, "CHANNEL_NOT_FOUND", "notification channel not found")
	ErrChannelNameTaken = pcerr.New(pcerr.AlreadyExists, "CHANNEL_EXISTS", "a channel with this name exists")
	ErrChannelLimit     = pcerr.New(pcerr.FailedPrecondition, "CHANNEL_LIMIT", "the Community edition allows 3 notification channels")
	ErrInvalidChannel   = pcerr.New(pcerr.InvalidArgument, "INVALID_CHANNEL", "invalid channel settings")
	ErrInvalidURL       = pcerr.New(pcerr.InvalidArgument, "INVALID_CHANNEL_URL", "the URL must be https, public and not PantherClaw itself (Slack: https://hooks.slack.com/services/...)")
	ErrNotAWebhook      = pcerr.New(pcerr.FailedPrecondition, "NOT_A_WEBHOOK", "only webhook channels have a signing secret")
	ErrNoUsableSecret   = pcerr.New(pcerr.Internal, "SECRET_UNAVAILABLE", "the channel secret could not be opened")
	// ErrSlackEdition: Slack approval cards are a Team edition feature
	// (G0 M14 D22).
	ErrSlackEdition      = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "Slack approval cards need the Team edition or above")
	errEditionUnreadable = errors.New("notifications: edition unavailable")
)

// Editions reports the deployment's edition (billing.Service).
type Editions interface {
	Current(ctx context.Context) (billingdomain.Entitlements, error)
}

// SetEditions sets the edition source used for the channel limit; without
// one, Community limits apply.
func (s *Service) SetEditions(e Editions) { s.editions = e }

// ChannelView is a channel without its secrets.
type ChannelView struct {
	ID                   ids.UUID
	Name                 string
	Kind                 domain.Kind
	State, PauseReason   string
	EventTypes           []string
	MinSeverity          domain.Severity
	RecipientRole        string
	URL                  string // webhook endpoints only; Slack URLs are secrets
	Health               domain.Health
	ConsecutiveFailures  int
	LastSuccess          *time.Time
	LastFailure          *time.Time
	LastFailureCode      string
	PreviousSecretExpiry *time.Time
	// SignatureScheme is hmac (the default) or hmac+ed25519 (G0 M20 D251).
	SignatureScheme      domain.SignatureScheme
	CreatedAt, UpdatedAt time.Time
	// SlackApp is a slack_app channel's configuration (nil for other kinds).
	SlackApp *SlackAppView
}

func channelView(c dbq.PcNotificationChannel) ChannelView {
	v := ChannelView{
		ID: c.ID, Name: c.Name, Kind: domain.Kind(c.Kind), State: c.State, PauseReason: deref(c.PauseReason),
		EventTypes: c.EventTypes, MinSeverity: domain.Severity(c.MinSeverity), RecipientRole: deref(c.RecipientRole),
		Health: domain.HealthOf(int(c.ConsecutiveFailures)), ConsecutiveFailures: int(c.ConsecutiveFailures),
		LastSuccess: c.LastSuccessAt, LastFailure: c.LastFailureAt, LastFailureCode: deref(c.LastFailureCode),
		PreviousSecretExpiry: c.PrevSecretExpiresAt, CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
		SignatureScheme: domain.SignatureScheme(c.SignatureScheme),
	}
	if v.Kind == domain.KindWebhook {
		v.URL = deref(c.Url)
	}
	return v
}

// DeliveryView is one delivery.
type DeliveryView struct {
	ID, Notification   ids.UUID
	NotificationType   string
	Channel, Recipient *ids.UUID
	Kind               domain.Kind
	State              string
	Attempts           int
	LastStatus         *int32
	LastError          string
	CreatedAt          time.Time
	NextAttempt        *time.Time
	FinishedAt         *time.Time
}

// inOrg runs fn for an authenticated caller holding perm at org scope.
func (s *Service) inOrg(ctx context.Context, perm td.Permission, fn func(context.Context, tapp.Caller, *dbq.Queries, db.TenantTx) error, opts ...db.TxOption) error {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if err := c.Require(perm, td.OrgPath(c.Org)); err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, c, dbq.New(tx), tx)
	}, opts...)
}

func (s *Service) channelLimit(ctx context.Context) (int, error) {
	if s.editions == nil {
		return CommunityChannelLimit, nil
	}
	e, err := s.editions.Current(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errEditionUnreadable, err)
	}
	if e.Edition == billingdomain.Community {
		return CommunityChannelLimit, nil
	}
	return -1, nil
}

// ChannelInput describes a new channel (from the API).
type ChannelInput struct {
	Name          string
	Kind          domain.Kind
	EventTypes    []string
	MinSeverity   domain.Severity
	RecipientRole string
	URL           string
	// SlackApp is a slack_app channel's configuration (G0 M14 D22).
	SlackApp *domain.SlackAppConfig
	// TeamsApp is a teams_app channel's configuration (G0 M20 D256).
	TeamsApp *domain.TeamsAppConfig
}

// CreateChannel adds a channel (notification.manage); the webhook signing
// secret is returned once.
func (s *Service) CreateChannel(ctx context.Context, in ChannelInput) (ChannelView, string, error) {
	if (in.Kind == domain.KindSlackApp) != (in.SlackApp != nil) {
		return ChannelView{}, "", ErrInvalidChannel
	}
	if (in.Kind == domain.KindTeamsApp) != (in.TeamsApp != nil) {
		return ChannelView{}, "", ErrInvalidChannel
	}
	if in.Kind == domain.KindSlackApp || in.Kind == domain.KindTeamsApp {
		if err := s.requireSlackApprovals(ctx); err != nil {
			return ChannelView{}, "", err
		}
	}
	limit, err := s.channelLimit(ctx)
	if err != nil {
		return ChannelView{}, "", err
	}
	var out ChannelView
	var secret string
	err = s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if limit >= 0 {
			n, err := q.CountLiveChannels(ctx, c.Org)
			if err != nil {
				return err
			}
			if int(n) >= limit {
				return ErrChannelLimit
			}
		}
		created, err := s.CreateChannelTx(ctx, tx, NewChannel{
			Org: c.Org, Name: in.Name, Kind: in.Kind, EventTypes: in.EventTypes, MinSeverity: in.MinSeverity,
			RecipientRole: in.RecipientRole, URL: in.URL, CreatedBy: c.Actor().Type + ":" + c.Actor().ID,
			SlackApp: in.SlackApp, TeamsApp: in.TeamsApp,
		})
		if err != nil {
			return apiError(err)
		}
		secret = created.Secret
		row, err := q.GetChannel(ctx, c.Org, created.ID)
		if err != nil {
			return err
		}
		if out, err = s.withSlackApp(ctx, q, c.Org, channelView(row)); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "notification.channel_created", created.ID, map[string]string{"kind": string(in.Kind), "name": in.Name})
	})
	return out, secret, err
}

// apiError maps validation errors to API errors.
func apiError(err error) error {
	switch {
	case errors.Is(err, ErrChannelExists):
		return ErrChannelNameTaken
	case errors.Is(err, domain.ErrBadURL), errors.Is(err, domain.ErrOwnHost), errors.Is(err, domain.ErrPrivateURL),
		errors.Is(err, domain.ErrSlackURL):
		return ErrInvalidURL
	case errors.Is(err, domain.ErrInvalid):
		return ErrInvalidChannel
	}
	return err
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, c tapp.Caller, event string, channel ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: event, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "notification_channel", ID: channel.String()}, Details: details,
	})
	return err
}

// GetChannel returns a channel and its last deliveries (notification.read).
func (s *Service) GetChannel(ctx context.Context, id ids.UUID) (ChannelView, []DeliveryView, error) {
	var out ChannelView
	var recent []DeliveryView
	err := s.inOrg(ctx, td.PermNotificationRead, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, _ db.TenantTx) error {
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return notFoundAs(err, ErrChannelNotFound)
		}
		if out, err = s.withSlackApp(ctx, q, c.Org, channelView(row)); err != nil {
			return err
		}
		rows, err := q.ListDeliveries(ctx, dbq.ListDeliveriesParams{OrgID: c.Org, ChannelID: &id, PageLimit: recentDeliveries})
		if err != nil {
			return err
		}
		recent = deliveryViews(rows)
		return nil
	}, db.ReadOnly())
	return out, recent, err
}

// ListChannels lists the org's channels (notification.read).
func (s *Service) ListChannels(ctx context.Context, pr page.Request) ([]ChannelView, string, error) {
	var out []ChannelView
	var next string
	err := s.inOrg(ctx, td.PermNotificationRead, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, _ db.TenantTx) error {
		rows, err := q.ListChannels(ctx, c.Org, cursor(pr), pr.Limit())
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.PcNotificationChannel) ids.UUID { return r.ID })
		for _, r := range rows {
			out = append(out, channelView(r))
		}
		return s.withSlackApps(ctx, q, c.Org, out)
	}, db.ReadOnly())
	return out, next, err
}

// ChannelUpdate changes the fields that are set.
type ChannelUpdate struct {
	Name        *string
	EventTypes  []string
	MinSeverity *domain.Severity
	Paused      *bool
	// SlackBotToken gives a slack_app channel a new bot token, which puts it
	// back to PENDING_ACTIVATION until confirmed with a key (G0 M14 D66).
	SlackBotToken *string
}

// UpdateChannel changes a channel (notification.manage). Its destination
// never changes.
func (s *Service) UpdateChannel(ctx context.Context, id ids.UUID, u ChannelUpdate) (ChannelView, error) {
	if u.Name != nil && !domain.ValidChannelName(*u.Name) {
		return ChannelView{}, ErrInvalidChannel
	}
	if len(u.EventTypes) > 0 && domain.ValidEventTypes(u.EventTypes) != nil {
		return ChannelView{}, ErrInvalidChannel
	}
	if u.MinSeverity != nil && !u.MinSeverity.Valid() {
		return ChannelView{}, ErrInvalidChannel
	}
	if u.SlackBotToken != nil && !slackTokenPattern.MatchString(*u.SlackBotToken) {
		return ChannelView{}, ErrInvalidChannel
	}
	var out ChannelView
	err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		p := dbq.UpdateChannelParams{Name: u.Name, OrgID: c.Org, ID: id}
		if len(u.EventTypes) > 0 {
			p.EventTypes = u.EventTypes
		}
		if u.MinSeverity != nil {
			sev := string(*u.MinSeverity)
			p.MinSeverity = &sev
		}
		n, err := q.UpdateChannel(ctx, p)
		if db.IsUniqueViolation(err) {
			return ErrChannelNameTaken
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrChannelNotFound
		}
		if err := s.slackChannelUpdate(ctx, tx, q, c, id, u); err != nil {
			return err
		}
		details := map[string]string{}
		if u.Paused != nil {
			if _, err := q.SetChannelPaused(ctx, *u.Paused, c.Org, id); err != nil {
				return err
			}
			details["paused"] = fmt.Sprint(*u.Paused)
		}
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if out, err = s.withSlackApp(ctx, q, c.Org, channelView(row)); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "notification.channel_updated", id, details)
	})
	return out, err
}

// DeleteChannel deletes a channel and cancels its pending deliveries
// (notification.manage).
func (s *Service) DeleteChannel(ctx context.Context, id ids.UUID) error {
	return s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		n, err := q.DisableChannel(ctx, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrChannelNotFound
		}
		if _, err := q.CancelPendingDeliveries(ctx, c.Org, &id); err != nil {
			return err
		}
		return s.audit(ctx, tx, c, "notification.channel_deleted", id, nil)
	})
}

// RotateChannelSecret gives a webhook channel a new signing secret,
// returned once; the old one keeps signing for SecretOverlap
// (notification.manage).
func (s *Service) RotateChannelSecret(ctx context.Context, id ids.UUID) (string, time.Time, error) {
	var shown string
	var until time.Time
	err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		cur, err := q.LockChannelSecret(ctx, c.Org, id)
		if err != nil {
			return notFoundAs(err, ErrChannelNotFound)
		}
		if domain.Kind(cur.Kind) != domain.KindWebhook {
			return ErrNotAWebhook
		}
		old, err := s.envelope.Decrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, cur.Secret)
		if err != nil {
			return ErrNoUsableSecret
		}
		// The old secret moves to prev_secret: re-encrypted, because the
		// AAD binds the column (HR-062).
		prev, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, prevSecretColumn), SecretPurpose, old)
		if err != nil {
			return err
		}
		fresh, err := domain.NewSigningSecret()
		if err != nil {
			return err
		}
		blob, err := s.envelope.Encrypt(ctx, s.field(c.Org, id, secretColumn), SecretPurpose, fresh)
		if err != nil {
			return err
		}
		exp, err := q.RotateChannelSecret(ctx, dbq.RotateChannelSecretParams{
			Secret: blob, PrevSecret: prev, OverlapSeconds: int32(SecretOverlap / time.Second), OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if exp != nil {
			until = *exp
		}
		shown = domain.FormatSecret(fresh)
		return s.audit(ctx, tx, c, "notification.channel_secret_rotated", id, nil)
	})
	return shown, until, err
}

// TestChannel sends a test notification to one channel
// (notification.manage).
func (s *Service) TestChannel(ctx context.Context, id ids.UUID) (ids.UUID, error) {
	var note ids.UUID
	err := s.inOrg(ctx, td.PermNotificationManage, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, tx db.TenantTx) error {
		row, err := q.GetChannel(ctx, c.Org, id)
		if err != nil {
			return notFoundAs(err, ErrChannelNotFound)
		}
		out, err := s.Enqueue(ctx, tx, Message{
			Org: c.Org, Type: "channel.test", Params: map[string]string{"channel": row.Name}, OnlyChannel: &id,
			Subject: &Subject{Type: "notification_channel", ID: id}, TTL: time.Hour,
		})
		if err != nil {
			return err
		}
		note = out.Notification
		return s.audit(ctx, tx, c, "notification.channel_tested", id, nil)
	})
	return note, err
}

// DeliveryFilter narrows ListDeliveries.
type DeliveryFilter struct {
	Channel *ids.UUID
	State   string
}

// ListDeliveries lists deliveries, newest first (notification.read).
func (s *Service) ListDeliveries(ctx context.Context, f DeliveryFilter, pr page.Request) ([]DeliveryView, string, error) {
	var out []DeliveryView
	var next string
	err := s.inOrg(ctx, td.PermNotificationRead, func(ctx context.Context, c tapp.Caller, q *dbq.Queries, _ db.TenantTx) error {
		p := dbq.ListDeliveriesParams{OrgID: c.Org, ChannelID: f.Channel, Before: cursor(pr), PageLimit: pr.Limit()}
		if f.State != "" {
			p.State = &f.State
		}
		rows, err := q.ListDeliveries(ctx, p)
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.ListDeliveriesRow) ids.UUID { return r.ID })
		out = deliveryViews(rows)
		return nil
	}, db.ReadOnly())
	return out, next, err
}

func deliveryViews(rows []dbq.ListDeliveriesRow) []DeliveryView {
	out := make([]DeliveryView, len(rows))
	for i, r := range rows {
		out[i] = DeliveryView{
			ID: r.ID, Notification: r.NotificationID, NotificationType: r.NotificationType, Channel: r.ChannelID,
			Recipient: r.RecipientUserID, Kind: domain.Kind(r.Kind), State: r.State, Attempts: int(r.Attempts),
			LastStatus: r.LastStatus, LastError: deref(r.LastError), CreatedAt: r.CreatedAt, NextAttempt: r.NextAttemptAt,
			FinishedAt: r.FinishedAt,
		}
	}
	return out
}

func notFoundAs(err, as error) error {
	if db.IsNoRows(err) {
		return as
	}
	return err
}

// cursor is the page cursor, nil on the first page.
func cursor(pr page.Request) *ids.UUID {
	if pr.After.IsZero() {
		return nil
	}
	a := pr.After
	return &a
}
