// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package webhookkeysrpc serves WebhookKeyService over Connect (G0 M20
// D261).
package webhookkeysrpc

import (
	"context"
	"encoding/base64"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/webhookkeys"
)

// Handler implements WebhookKeyServiceHandler.
type Handler struct{ svc *webhookkeys.Service }

// New returns the handler.
func New(svc *webhookkeys.Service) *Handler { return &Handler{svc: svc} }

var _ pantherclawv1connect.WebhookKeyServiceHandler = (*Handler)(nil)

func keyProto(k keystore.WebhookKey) *pantherclawv1.WebhookKey {
	out := &pantherclawv1.WebhookKey{
		Kid: k.KID, State: string(k.State), PublicKey: base64.RawURLEncoding.EncodeToString(k.Public),
		CreateTime: timestamppb.New(k.CreatedAt),
	}
	if !k.RetiresAt.IsZero() {
		out.RetireTime = timestamppb.New(k.RetiresAt)
	}
	return out
}

// ListWebhookKeys implements WebhookKeyServiceHandler.
func (h *Handler) ListWebhookKeys(ctx context.Context, _ *pantherclawv1.ListWebhookKeysRequest) (*pantherclawv1.ListWebhookKeysResponse, error) {
	ks, jwks, err := h.svc.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListWebhookKeysResponse{JwksUrl: jwks}
	for _, k := range ks {
		out.Keys = append(out.Keys, keyProto(k))
	}
	return out, nil
}

// RotateWebhookKey implements WebhookKeyServiceHandler; over the API it
// answers STEP_UP_REQUIRED (no browser session step-up).
func (h *Handler) RotateWebhookKey(ctx context.Context, _ *pantherclawv1.RotateWebhookKeyRequest) (*pantherclawv1.RotateWebhookKeyResponse, error) {
	k, retiring, err := h.svc.Rotate(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateWebhookKeyResponse{Key: keyProto(k), RetiringKid: retiring}, nil
}
