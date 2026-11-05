// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package caprpc serves PaymentCapService over Connect (G0 M39 D1124,
// D1124a; HR-835, HR-836).
package caprpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/payments/caps"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves PaymentCapService.
type Handler struct {
	pantherclawv1connect.UnimplementedPaymentCapServiceHandler
	svc *caps.Service
}

// New returns the PaymentCapService handler.
func New(svc *caps.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// ProposePaymentCap implements PaymentCapServiceHandler.
func (h *Handler) ProposePaymentCap(ctx context.Context, req *pantherclawv1.ProposePaymentCapRequest) (
	*pantherclawv1.ProposePaymentCapResponse, error,
) {
	c, err := h.svc.Propose(ctx, caps.Proposal{
		Merchant: req.GetMerchant(), Currency: req.GetCurrency(),
		MaxPerPaymentMinor: req.GetMaxPerPaymentMinor(), MaxPerDayMinor: req.GetMaxPerDayMinor(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ProposePaymentCapResponse{Cap: proto(c)}, nil
}

// ListPaymentCaps implements PaymentCapServiceHandler.
func (h *Handler) ListPaymentCaps(ctx context.Context, req *pantherclawv1.ListPaymentCapsRequest) (
	*pantherclawv1.ListPaymentCapsResponse, error,
) {
	var f caps.Filter
	if s := req.GetState(); s != "" {
		f.State = &s
	}
	if m := req.GetMerchant(); m != "" {
		f.Merchant = &m
	}
	list, next, err := h.svc.List(ctx, f, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPaymentCapsResponse{NextPageToken: next}
	for _, c := range list {
		out.Caps = append(out.Caps, proto(c))
	}
	return out, nil
}

// RetirePaymentCap implements PaymentCapServiceHandler.
func (h *Handler) RetirePaymentCap(ctx context.Context, req *pantherclawv1.RetirePaymentCapRequest) (
	*pantherclawv1.RetirePaymentCapResponse, error,
) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	c, err := h.svc.Retire(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetirePaymentCapResponse{Cap: proto(c)}, nil
}

// SetMerchantAudience implements PaymentCapServiceHandler (G0 M39 D1124c).
func (h *Handler) SetMerchantAudience(ctx context.Context, req *pantherclawv1.SetMerchantAudienceRequest) (
	*pantherclawv1.SetMerchantAudienceResponse, error,
) {
	id, err := ids.ParseUUID(req.GetConnectionId())
	if err != nil {
		return nil, errInvalidID
	}
	if err := h.svc.SetMerchantAudience(ctx, id, req.GetMerchantAudience()); err != nil {
		return nil, err
	}
	return &pantherclawv1.SetMerchantAudienceResponse{}, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func proto(c caps.Cap) *pantherclawv1.PaymentCap {
	out := &pantherclawv1.PaymentCap{
		Id: c.ID.String(), Merchant: c.Merchant, Currency: c.Currency,
		MaxPerPaymentMinor: c.MaxPerPaymentMinor, MaxPerDayMinor: c.MaxPerDayMinor, State: c.State,
		CreatedBy: c.CreatedBy, CreateTime: timestamppb.New(c.CreatedAt), ChangeRequestUrl: c.ChangeRequestURL,
		ActivateTime: ts(c.ActivatedAt), RetireTime: ts(c.RetiredAt), RetiredBy: c.RetiredBy,
	}
	if !c.ChangeRequest.IsZero() {
		out.ChangeRequestId = c.ChangeRequest.String()
	}
	for _, a := range c.ApprovedBy {
		out.ApprovedBy = append(out.ApprovedBy, a.String())
	}
	return out
}
