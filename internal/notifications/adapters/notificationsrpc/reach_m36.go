// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package notificationsrpc

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// Approval reach (G0 M36 D1065, D1066): a person's own preferences and
// Web Push subscriptions.

var approvalDeliveries = map[string]pantherclawv1.ApprovalDelivery{
	domain.DeliveryImmediate: pantherclawv1.ApprovalDelivery_APPROVAL_DELIVERY_IMMEDIATE,
	domain.DeliveryDigest:    pantherclawv1.ApprovalDelivery_APPROVAL_DELIVERY_DIGEST,
}

func preferencesProto(p domain.Preferences) *pantherclawv1.NotificationPreferences {
	out := &pantherclawv1.NotificationPreferences{
		ApprovalDelivery: approvalDeliveries[p.Delivery], DigestMinutes: int32(p.DigestMinutes), //nolint:gosec // 15, 30 or 60
		QuietStart: p.QuietStart, QuietEnd: p.QuietEnd, TimeZone: p.TimeZone,
	}
	if !p.UpdatedAt.IsZero() {
		out.UpdateTime = ts(p.UpdatedAt)
	}
	return out
}

// GetMyNotificationPreferences implements NotificationService.
func (h *Handler) GetMyNotificationPreferences(ctx context.Context, _ *pantherclawv1.GetMyNotificationPreferencesRequest) (
	*pantherclawv1.GetMyNotificationPreferencesResponse, error,
) {
	p, err := h.s.MyPreferences(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetMyNotificationPreferencesResponse{Preferences: preferencesProto(p)}, nil
}

// SetMyNotificationPreferences implements NotificationService.
func (h *Handler) SetMyNotificationPreferences(ctx context.Context, req *pantherclawv1.SetMyNotificationPreferencesRequest) (
	*pantherclawv1.SetMyNotificationPreferencesResponse, error,
) {
	p := domain.Preferences{
		DigestMinutes: int(req.GetDigestMinutes()), QuietStart: req.GetQuietStart(), QuietEnd: req.GetQuietEnd(),
		TimeZone: req.GetTimeZone(),
	}
	for d, v := range approvalDeliveries {
		if v == req.GetApprovalDelivery() {
			p.Delivery = d
		}
	}
	out, err := h.s.SetMyPreferences(ctx, p)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetMyNotificationPreferencesResponse{Preferences: preferencesProto(out)}, nil
}

// GetWebPushKey implements NotificationService.
func (h *Handler) GetWebPushKey(ctx context.Context, _ *pantherclawv1.GetWebPushKeyRequest) (*pantherclawv1.GetWebPushKeyResponse, error) {
	k, err := h.s.WebPushKey(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetWebPushKeyResponse{ApplicationServerKey: k}, nil
}

func pushProto(p napp.PushSubscription) *pantherclawv1.PushSubscription {
	out := &pantherclawv1.PushSubscription{
		Id: p.ID.String(), EndpointHost: p.EndpointHost, Label: p.Label, CreateTime: ts(p.Created),
		FailureCount: int32(min(p.FailureCount, 1<<30)), //nolint:gosec // bounded
	}
	if p.LastSuccess != nil {
		out.LastSuccessTime = ts(*p.LastSuccess)
	}
	return out
}

// RegisterPushSubscription implements NotificationService.
func (h *Handler) RegisterPushSubscription(ctx context.Context, req *pantherclawv1.RegisterPushSubscriptionRequest) (
	*pantherclawv1.RegisterPushSubscriptionResponse, error,
) {
	p, err := h.s.RegisterPushSubscription(ctx, req.GetEndpoint(), req.GetP256Dh(), req.GetAuth(), req.GetLabel())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RegisterPushSubscriptionResponse{Subscription: pushProto(p)}, nil
}

// RemovePushSubscription implements NotificationService.
func (h *Handler) RemovePushSubscription(ctx context.Context, req *pantherclawv1.RemovePushSubscriptionRequest) (
	*pantherclawv1.RemovePushSubscriptionResponse, error,
) {
	id, err := linkID(req.GetId())
	if err != nil {
		return nil, err
	}
	if err := h.s.RemovePushSubscription(ctx, id); err != nil {
		return nil, err
	}
	return &pantherclawv1.RemovePushSubscriptionResponse{}, nil
}

// ListMyPushSubscriptions implements NotificationService.
func (h *Handler) ListMyPushSubscriptions(ctx context.Context, _ *pantherclawv1.ListMyPushSubscriptionsRequest) (
	*pantherclawv1.ListMyPushSubscriptionsResponse, error,
) {
	ps, err := h.s.MyPushSubscriptions(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListMyPushSubscriptionsResponse{}
	for _, p := range ps {
		out.Subscriptions = append(out.Subscriptions, pushProto(p))
	}
	return out, nil
}
