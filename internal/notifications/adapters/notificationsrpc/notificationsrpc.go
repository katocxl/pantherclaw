// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package notificationsrpc serves NotificationService over Connect
// (G0 M5 part 1, HR-157..159).
package notificationsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// Handler implements NotificationServiceHandler.
type Handler struct {
	s *napp.Service
}

// New returns the handler.
func New(s *napp.Service) *Handler { return &Handler{s: s} }

var _ pantherclawv1connect.NotificationServiceHandler = (*Handler)(nil)

var (
	kinds = map[pantherclawv1.ChannelKind]domain.Kind{
		pantherclawv1.ChannelKind_CHANNEL_KIND_LOG: domain.KindLog, pantherclawv1.ChannelKind_CHANNEL_KIND_EMAIL: domain.KindEmail,
		pantherclawv1.ChannelKind_CHANNEL_KIND_SLACK: domain.KindSlack, pantherclawv1.ChannelKind_CHANNEL_KIND_WEBHOOK: domain.KindWebhook,
		pantherclawv1.ChannelKind_CHANNEL_KIND_SLACK_APP: domain.KindSlackApp,
	}
	severities = map[pantherclawv1.NotificationSeverity]domain.Severity{
		pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_INFO:     domain.Info,
		pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_WARNING:  domain.Warning,
		pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_CRITICAL: domain.Critical,
	}
	healths = map[domain.Health]pantherclawv1.ChannelHealth{
		domain.Healthy: pantherclawv1.ChannelHealth_CHANNEL_HEALTH_HEALTHY, domain.Degraded: pantherclawv1.ChannelHealth_CHANNEL_HEALTH_DEGRADED,
		domain.Failing: pantherclawv1.ChannelHealth_CHANNEL_HEALTH_FAILING,
	}
	deliveryStates = map[string]pantherclawv1.DeliveryState{
		"PENDING": pantherclawv1.DeliveryState_DELIVERY_STATE_PENDING, "DELIVERED": pantherclawv1.DeliveryState_DELIVERY_STATE_DELIVERED,
		"FAILED": pantherclawv1.DeliveryState_DELIVERY_STATE_FAILED, "EXPIRED": pantherclawv1.DeliveryState_DELIVERY_STATE_EXPIRED,
		"SKIPPED": pantherclawv1.DeliveryState_DELIVERY_STATE_SKIPPED, "DROPPED": pantherclawv1.DeliveryState_DELIVERY_STATE_DROPPED,
		"CANCELLED": pantherclawv1.DeliveryState_DELIVERY_STATE_CANCELED, //nolint:misspell // the schema's state name
	}
)

func kindOf(k domain.Kind) pantherclawv1.ChannelKind {
	for p, d := range kinds {
		if d == k {
			return p
		}
	}
	return pantherclawv1.ChannelKind_CHANNEL_KIND_UNSPECIFIED
}

func severityOf(s domain.Severity) pantherclawv1.NotificationSeverity {
	for p, d := range severities {
		if d == s {
			return p
		}
	}
	return pantherclawv1.NotificationSeverity_NOTIFICATION_SEVERITY_UNSPECIFIED
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func channel(c napp.ChannelView) *pantherclawv1.Channel {
	state := pantherclawv1.ChannelState_CHANNEL_STATE_ACTIVE
	if c.State == "PAUSED" {
		state = pantherclawv1.ChannelState_CHANNEL_STATE_PAUSED
	}
	pause := c.PauseReason
	if c.SlackApp != nil && c.SlackApp.State != napp.SlackActive {
		// A slack_app channel posts nothing until activated with a step-up.
		state, pause = pantherclawv1.ChannelState_CHANNEL_STATE_PAUSED, "AWAITING_ACTIVATION"
	}
	out := &pantherclawv1.Channel{
		Id: c.ID.String(), Name: c.Name, Kind: kindOf(c.Kind), State: state, PauseReason: pause,
		EventTypes: c.EventTypes, MinSeverity: severityOf(c.MinSeverity), RecipientRole: c.RecipientRole, Url: c.URL,
		Health: healths[c.Health], ConsecutiveFailures: int32(min(c.ConsecutiveFailures, 1<<30)), //nolint:gosec // G115: bounded
		LastSuccessTime: tsp(c.LastSuccess), LastFailureTime: tsp(c.LastFailure), LastFailureCode: c.LastFailureCode,
		PreviousSecretExpireTime: tsp(c.PreviousSecretExpiry), CreateTime: ts(c.CreatedAt), UpdateTime: ts(c.UpdatedAt),
		SignatureScheme: string(c.SignatureScheme),
	}
	if c.SlackApp != nil {
		level := pantherclawv1.SlackDataLevel_SLACK_DATA_LEVEL_MINIMAL
		if c.SlackApp.DataLevel == domain.SlackSummary {
			level = pantherclawv1.SlackDataLevel_SLACK_DATA_LEVEL_SUMMARY
		}
		out.SlackApp = &pantherclawv1.SlackAppConfig{ChannelId: c.SlackApp.ChannelID, DataLevel: level, TeamId: c.SlackApp.TeamID}
	}
	return out
}

func deliveries(in []napp.DeliveryView) []*pantherclawv1.Delivery {
	out := make([]*pantherclawv1.Delivery, len(in))
	for i, d := range in {
		p := &pantherclawv1.Delivery{
			Id: d.ID.String(), NotificationId: d.Notification.String(), NotificationType: d.NotificationType,
			Kind: kindOf(d.Kind), State: deliveryStates[d.State], Attempts: int32(min(d.Attempts, 1<<30)), //nolint:gosec // G115: bounded
			LastError: d.LastError, CreateTime: ts(d.CreatedAt), NextAttemptTime: tsp(d.NextAttempt), FinishTime: tsp(d.FinishedAt),
		}
		if d.Channel != nil {
			p.ChannelId = d.Channel.String()
		}
		if d.Recipient != nil {
			p.RecipientUserId = d.Recipient.String()
		}
		if d.LastStatus != nil {
			p.LastStatus = *d.LastStatus
		}
		out[i] = p
	}
	return out
}

func parse(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

// CreateChannel implements NotificationServiceHandler.
func (h *Handler) CreateChannel(ctx context.Context, req *pantherclawv1.CreateChannelRequest) (*pantherclawv1.CreateChannelResponse, error) {
	sev := severities[req.GetMinSeverity()]
	c, secret, err := h.s.CreateChannel(ctx, napp.ChannelInput{
		Name: req.GetName(), Kind: kinds[req.GetKind()], EventTypes: req.GetEventTypes(), MinSeverity: sev,
		RecipientRole: req.GetRecipientRole(), URL: req.GetUrl(),
		SlackApp: slackAppIn(req.GetSlackApp()),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateChannelResponse{Channel: channel(c), SigningSecret: secret}, nil
}

// GetChannel implements NotificationServiceHandler.
func (h *Handler) GetChannel(ctx context.Context, req *pantherclawv1.GetChannelRequest) (*pantherclawv1.GetChannelResponse, error) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	c, recent, err := h.s.GetChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetChannelResponse{Channel: channel(c), RecentDeliveries: deliveries(recent)}, nil
}

// ListChannels implements NotificationServiceHandler.
func (h *Handler) ListChannels(ctx context.Context, req *pantherclawv1.ListChannelsRequest) (*pantherclawv1.ListChannelsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	cs, next, err := h.s.ListChannels(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListChannelsResponse{NextPageToken: next}
	for _, c := range cs {
		out.Channels = append(out.Channels, channel(c))
	}
	return out, nil
}

// UpdateChannel implements NotificationServiceHandler.
func (h *Handler) UpdateChannel(ctx context.Context, req *pantherclawv1.UpdateChannelRequest) (*pantherclawv1.UpdateChannelResponse, error) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	u := napp.ChannelUpdate{EventTypes: req.GetEventTypes()}
	if req.Name != nil {
		u.Name = req.Name
	}
	if req.MinSeverity != nil {
		sev := severities[req.GetMinSeverity()]
		u.MinSeverity = &sev
	}
	if req.Paused != nil {
		u.Paused = req.Paused
	}
	if req.SlackBotToken != nil {
		u.SlackBotToken = req.SlackBotToken // G0 M14 D66: back to PENDING_ACTIVATION
	}
	c, err := h.s.UpdateChannel(ctx, id, u)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateChannelResponse{Channel: channel(c)}, nil
}

// DeleteChannel implements NotificationServiceHandler.
func (h *Handler) DeleteChannel(ctx context.Context, req *pantherclawv1.DeleteChannelRequest) (*pantherclawv1.DeleteChannelResponse, error) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	if err := h.s.DeleteChannel(ctx, id); err != nil {
		return nil, err
	}
	return &pantherclawv1.DeleteChannelResponse{}, nil
}

// RotateChannelSecret implements NotificationServiceHandler.
func (h *Handler) RotateChannelSecret(ctx context.Context, req *pantherclawv1.RotateChannelSecretRequest) (*pantherclawv1.RotateChannelSecretResponse, error) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	secret, until, err := h.s.RotateChannelSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateChannelSecretResponse{SigningSecret: secret, PreviousSecretExpireTime: ts(until)}, nil
}

// TestChannel implements NotificationServiceHandler.
func (h *Handler) TestChannel(ctx context.Context, req *pantherclawv1.TestChannelRequest) (*pantherclawv1.TestChannelResponse, error) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	note, err := h.s.TestChannel(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TestChannelResponse{NotificationId: note.String()}, nil
}

// ListDeliveries implements NotificationServiceHandler.
func (h *Handler) ListDeliveries(ctx context.Context, req *pantherclawv1.ListDeliveriesRequest) (*pantherclawv1.ListDeliveriesResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var f napp.DeliveryFilter
	if req.GetChannelId() != "" {
		id, err := parse(req.GetChannelId())
		if err != nil {
			return nil, err
		}
		f.Channel = &id
	}
	for name, st := range deliveryStates {
		if st == req.GetState() {
			f.State = name
		}
	}
	ds, next, err := h.s.ListDeliveries(ctx, f, pr)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ListDeliveriesResponse{Deliveries: deliveries(ds), NextPageToken: next}, nil
}

// slackAppIn is a slack_app configuration from the wire; nil when absent.
// The team id is the server's to read from Slack, never the caller's.
func slackAppIn(c *pantherclawv1.SlackAppConfig) *domain.SlackAppConfig {
	if c == nil {
		return nil
	}
	level := domain.SlackMinimal
	if c.GetDataLevel() == pantherclawv1.SlackDataLevel_SLACK_DATA_LEVEL_SUMMARY {
		level = domain.SlackSummary
	}
	return &domain.SlackAppConfig{ChannelID: c.GetChannelId(), DataLevel: level, BotToken: c.GetBotToken()}
}

// SetChannelSignatureScheme implements NotificationServiceHandler (G0 M20
// D251).
func (h *Handler) SetChannelSignatureScheme(ctx context.Context, req *pantherclawv1.SetChannelSignatureSchemeRequest) (
	*pantherclawv1.SetChannelSignatureSchemeResponse, error,
) {
	id, err := parse(req.GetId())
	if err != nil {
		return nil, err
	}
	c, jwks, err := h.s.SetChannelSignatureScheme(ctx, id, req.GetSignatureScheme())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetChannelSignatureSchemeResponse{Channel: channel(c), JwksUrl: jwks}, nil
}
