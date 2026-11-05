// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves PaymentsService over Connect (G0 M39 D1121, D1123;
// HR-830..832, HR-838): trust anchors and agent request signatures.
package app

import (
	"context"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/payments/anchors"
	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	"github.com/katocxl/pantherclaw/internal/payments/httpsig"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves PaymentsService.
type Handler struct {
	pantherclawv1connect.UnimplementedPaymentsServiceHandler
	svc *anchors.Service
}

// New returns the PaymentsService handler.
func New(svc *anchors.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreatePaymentTrustAnchor implements PaymentsServiceHandler.
func (h *Handler) CreatePaymentTrustAnchor(ctx context.Context, req *pantherclawv1.CreatePaymentTrustAnchorRequest) (
	*pantherclawv1.CreatePaymentTrustAnchorResponse, error,
) {
	a, err := h.svc.Create(ctx, anchors.NewAnchor{
		Kind: ap2.Kind(req.GetKind()), Name: req.GetName(), JWKS: req.GetJwks(), URL: req.GetUrl(), Sandbox: req.GetSandbox(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreatePaymentTrustAnchorResponse{Anchor: h.proto(a)}, nil
}

// ActivatePaymentTrustAnchor implements PaymentsServiceHandler: over the
// API it is always refused (STEP_UP_REQUIRED); a person activates an
// anchor on its page with a security key (HR-832).
func (h *Handler) ActivatePaymentTrustAnchor(ctx context.Context, req *pantherclawv1.ActivatePaymentTrustAnchorRequest) (
	*pantherclawv1.ActivatePaymentTrustAnchorResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Activate(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivatePaymentTrustAnchorResponse{Anchor: h.proto(a)}, nil
}

// RevokePaymentTrustAnchor implements PaymentsServiceHandler.
func (h *Handler) RevokePaymentTrustAnchor(ctx context.Context, req *pantherclawv1.RevokePaymentTrustAnchorRequest) (
	*pantherclawv1.RevokePaymentTrustAnchorResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Revoke(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokePaymentTrustAnchorResponse{Anchor: h.proto(a)}, nil
}

// ListPaymentTrustAnchors implements PaymentsServiceHandler.
func (h *Handler) ListPaymentTrustAnchors(ctx context.Context, req *pantherclawv1.ListPaymentTrustAnchorsRequest) (
	*pantherclawv1.ListPaymentTrustAnchorsResponse, error,
) {
	rows, next, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPaymentTrustAnchorsResponse{NextPageToken: next}
	for _, a := range rows {
		out.Anchors = append(out.Anchors, h.proto(a))
	}
	return out, nil
}

// GetPaymentTrustAnchor implements PaymentsServiceHandler.
func (h *Handler) GetPaymentTrustAnchor(ctx context.Context, req *pantherclawv1.GetPaymentTrustAnchorRequest) (
	*pantherclawv1.GetPaymentTrustAnchorResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPaymentTrustAnchorResponse{Anchor: h.proto(a)}, nil
}

// VerifyAgentSignature implements PaymentsServiceHandler.
func (h *Handler) VerifyAgentSignature(ctx context.Context, req *pantherclawv1.VerifyAgentSignatureRequest) (
	*pantherclawv1.VerifyAgentSignatureResponse, error,
) {
	hdr := http.Header{}
	for _, f := range req.GetHeaders() {
		hdr.Add(f.GetName(), f.GetValue())
	}
	r, err := h.svc.VerifyAgentSignature(ctx, httpsig.Request{
		Method: req.GetMethod(), Authority: req.GetAuthority(), Path: req.GetPath(), Header: hdr, Body: req.GetBody(),
	})
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.VerifyAgentSignatureResponse{
		Valid: r.Valid, Keyid: r.KeyID, Tag: r.Tag, AgentClaims: r.Claims, Reason: r.Reason,
	}
	if !r.AnchorID.IsZero() {
		out.AnchorId = r.AnchorID.String()
	}
	return out, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) proto(a anchors.TrustAnchor) *pantherclawv1.PaymentTrustAnchor {
	out := &pantherclawv1.PaymentTrustAnchor{
		Id: a.ID.String(), Kind: string(a.Kind), Name: a.Name, Jwks: a.JWKS, Url: a.URL, Sandbox: a.Sandbox, State: a.State,
		CreatedBy: a.CreatedBy, CreateTime: timestamppb.New(a.CreatedAt), ActivateTime: ts(a.ActivatedAt),
		RevokeTime: ts(a.RevokedAt), ConfirmUrl: h.svc.ConfirmURL(a.ID),
	}
	if a.ActivatedBy != nil {
		out.ActivatedBy = a.ActivatedBy.String()
	}
	return out
}
