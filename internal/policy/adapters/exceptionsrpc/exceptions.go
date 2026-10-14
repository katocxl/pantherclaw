// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package exceptionsrpc serves PolicyExceptionService over Connect (G0
// M11.1 D14, HR-235): narrow, expiring exceptions on exceptable policy
// rules, approved through change requests.
package exceptionsrpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
)

// Handler serves PolicyExceptionService.
type Handler struct {
	pantherclawv1connect.UnimplementedPolicyExceptionServiceHandler
	svc *exceptions.Service
}

// New returns the PolicyExceptionService handler.
func New(svc *exceptions.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func optID(s *string) (*ids.UUID, error) {
	if s == nil {
		return nil, nil //nolint:nilnil // unset
	}
	id, err := idOf(*s)
	return &id, err
}

// RequestPolicyException implements PolicyExceptionServiceHandler.
func (h *Handler) RequestPolicyException(ctx context.Context, req *pantherclawv1.RequestPolicyExceptionRequest) (
	*pantherclawv1.RequestPolicyExceptionResponse, error,
) {
	agent, err := idOf(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	owner, err := optID(req.OwnerId)
	if err != nil {
		return nil, err
	}
	x, cr, err := h.svc.RequestException(ctx, exceptions.Request{
		Rule: req.GetRuleId(), Agent: agent, Operations: req.GetOperations(), Reason: req.GetReason(),
		ExpiresIn: time.Duration(req.GetExpiresInSeconds()) * time.Second, Owner: owner,
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestPolicyExceptionResponse{
		Exception: Proto(x, x.State), ChangeRequestId: cr.ID.String(), ChangeRequestUrl: cr.URL,
	}, nil
}

// GetPolicyException implements PolicyExceptionServiceHandler.
func (h *Handler) GetPolicyException(ctx context.Context, req *pantherclawv1.GetPolicyExceptionRequest) (
	*pantherclawv1.GetPolicyExceptionResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	x, err := h.svc.GetException(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPolicyExceptionResponse{Exception: Proto(x.Exception, x.EffectiveState)}, nil
}

// ListPolicyExceptions implements PolicyExceptionServiceHandler.
func (h *Handler) ListPolicyExceptions(ctx context.Context, req *pantherclawv1.ListPolicyExceptionsRequest) (
	*pantherclawv1.ListPolicyExceptionsResponse, error,
) {
	agent, err := optID(req.AgentId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListExceptions(ctx, exceptions.Filter{Agent: agent, Rule: req.RuleId, State: req.State},
		req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyExceptionsResponse{NextPageToken: next}
	for _, x := range rows {
		out.Exceptions = append(out.Exceptions, Proto(x.Exception, x.EffectiveState))
	}
	return out, nil
}

// RevokePolicyException implements PolicyExceptionServiceHandler.
func (h *Handler) RevokePolicyException(ctx context.Context, req *pantherclawv1.RevokePolicyExceptionRequest) (
	*pantherclawv1.RevokePolicyExceptionResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	x, err := h.svc.RevokeException(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokePolicyExceptionResponse{Exception: Proto(x, x.State)}, nil
}

// Proto renders an exception with the state to show.
func Proto(x exceptions.Exception, state string) *pantherclawv1.PolicyException {
	out := &pantherclawv1.PolicyException{
		Id: x.ID.String(), BundleId: x.BundleID, RuleId: x.RuleID, RuleDigest: hex.EncodeToString(x.RuleDigest),
		AgentId: x.AgentID.String(), Operations: x.Operations, Reason: x.Reason, OwnerId: x.OwnerID.String(),
		RequestedBy: x.RequestedBy.String(), RequestedExpireTime: timestamppb.New(x.RequestedExpiry), State: state,
		CreateTime: timestamppb.New(x.CreatedAt),
	}
	if x.ActivatedAt != nil {
		out.ActivateTime = timestamppb.New(*x.ActivatedAt)
	}
	if x.ExpiresAt != nil {
		out.ExpireTime = timestamppb.New(*x.ExpiresAt)
	}
	if x.RevokedBy != nil {
		out.RevokedBy = x.RevokedBy.String()
	}
	if x.RevokedReason != nil {
		out.RevokedReason = *x.RevokedReason
	}
	return out
}
