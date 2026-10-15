// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package signalsrpc serves SharedSignalsService over Connect (G0 M10 D37;
// PN-024, HR-261).
package signalsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/signals"
)

// Handler serves SharedSignalsService.
type Handler struct {
	pantherclawv1connect.UnimplementedSharedSignalsServiceHandler
	svc *signals.Service
}

// New returns the SharedSignalsService handler.
func New(svc *signals.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreateSSFTransmitter implements SharedSignalsServiceHandler.
func (h *Handler) CreateSSFTransmitter(ctx context.Context, req *pantherclawv1.CreateSSFTransmitterRequest) (
	*pantherclawv1.CreateSSFTransmitterResponse, error,
) {
	t, err := h.svc.Create(ctx, signals.NewTransmitter{
		Name: req.GetName(), Issuer: req.GetIssuer(), JWKSURI: req.GetJwksUri(), Audience: req.GetAudience(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateSSFTransmitterResponse{Transmitter: h.proto(t)}, nil
}

// GetSSFTransmitter implements SharedSignalsServiceHandler.
func (h *Handler) GetSSFTransmitter(ctx context.Context, req *pantherclawv1.GetSSFTransmitterRequest) (
	*pantherclawv1.GetSSFTransmitterResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSSFTransmitterResponse{Transmitter: h.proto(t)}, nil
}

// ListSSFTransmitters implements SharedSignalsServiceHandler.
func (h *Handler) ListSSFTransmitters(ctx context.Context, req *pantherclawv1.ListSSFTransmittersRequest) (
	*pantherclawv1.ListSSFTransmittersResponse, error,
) {
	rows, next, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSSFTransmittersResponse{NextPageToken: next}
	for _, t := range rows {
		out.Transmitters = append(out.Transmitters, h.proto(t))
	}
	return out, nil
}

// SetSSFTransmitterState implements SharedSignalsServiceHandler.
func (h *Handler) SetSSFTransmitterState(ctx context.Context, req *pantherclawv1.SetSSFTransmitterStateRequest) (
	*pantherclawv1.SetSSFTransmitterStateResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.SetState(ctx, id, req.GetState())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetSSFTransmitterStateResponse{Transmitter: h.proto(t)}, nil
}

// ListSSFEvents implements SharedSignalsServiceHandler.
func (h *Handler) ListSSFEvents(ctx context.Context, req *pantherclawv1.ListSSFEventsRequest) (
	*pantherclawv1.ListSSFEventsResponse, error,
) {
	id, err := idOf(req.GetTransmitterId())
	if err != nil {
		return nil, err
	}
	rows, err := h.svc.Events(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSSFEventsResponse{}
	for _, e := range rows {
		p := &pantherclawv1.SSFEvent{
			Id: e.ID.String(), Jti: e.JTI, EventType: e.EventType, IssueTime: timestamppb.New(e.IssuedAt), SubjectFormat: e.SubjectFormat,
			MatchBasis: e.MatchBasis, Outcome: e.Outcome, ReceiveTime: timestamppb.New(e.ReceivedAt),
		}
		if e.User != nil {
			p.UserId = e.User.String()
		}
		if e.Case != nil {
			p.CaseId = e.Case.String()
		}
		out.Events = append(out.Events, p)
	}
	return out, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func (h *Handler) proto(t signals.Transmitter) *pantherclawv1.SSFTransmitter {
	out := &pantherclawv1.SSFTransmitter{
		Id: t.ID.String(), Name: t.Name, Issuer: t.Issuer, JwksUri: t.JWKSURI, Audience: t.Audience, State: t.State,
		EndpointUrl: t.EndpointURL, ConfirmUrl: h.svc.ConfirmURL(t.ID), CreatedBy: t.CreatedBy, CreateTime: timestamppb.New(t.CreatedAt),
		ActivateTime: ts(t.ActivatedAt), LastEventTime: ts(t.LastEventAt), EventsAccepted: t.EventsAccepted,
		EventsRefused: t.EventsRefused, LastRefusalTime: ts(t.LastRefusalAt), LastRefusalCode: t.LastRefusalCode,
	}
	if t.ActivatedBy != nil {
		out.ActivatedBy = t.ActivatedBy.String()
	}
	return out
}

// GetIdentityPlaybook implements SharedSignalsServiceHandler.
func (h *Handler) GetIdentityPlaybook(ctx context.Context, _ *pantherclawv1.GetIdentityPlaybookRequest) (
	*pantherclawv1.GetIdentityPlaybookResponse, error,
) {
	pb, err := h.svc.GetPlaybook(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.IdentityPlaybook{Enabled: pb.Enabled, Events: pb.Events, Version: int32(pb.Version)} //nolint:gosec // G115: a small counter
	if pb.Request != nil {
		out.RequestId = pb.Request.String()
		out.UpdateTime = timestamppb.New(pb.UpdatedAt)
	}
	return &pantherclawv1.GetIdentityPlaybookResponse{Playbook: out}, nil
}

// RequestIdentityPlaybookChange implements SharedSignalsServiceHandler.
func (h *Handler) RequestIdentityPlaybookChange(ctx context.Context, req *pantherclawv1.RequestIdentityPlaybookChangeRequest) (
	*pantherclawv1.RequestIdentityPlaybookChangeResponse, error,
) {
	r, err := h.svc.RequestPlaybookChange(ctx, req.GetKind(), req.GetEvents())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestIdentityPlaybookChangeResponse{Request: playbookRequest(r)}, nil
}

// ListIdentityPlaybookRequests implements SharedSignalsServiceHandler.
func (h *Handler) ListIdentityPlaybookRequests(ctx context.Context, _ *pantherclawv1.ListIdentityPlaybookRequestsRequest) (
	*pantherclawv1.ListIdentityPlaybookRequestsResponse, error,
) {
	rows, err := h.svc.PlaybookRequests(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListIdentityPlaybookRequestsResponse{}
	for _, r := range rows {
		out.Requests = append(out.Requests, playbookRequest(r))
	}
	return out, nil
}

// DeclineIdentityPlaybookRequest implements SharedSignalsServiceHandler.
func (h *Handler) DeclineIdentityPlaybookRequest(ctx context.Context, req *pantherclawv1.DeclineIdentityPlaybookRequestRequest) (
	*pantherclawv1.DeclineIdentityPlaybookRequestResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.DeclinePlaybookRequest(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DeclineIdentityPlaybookRequestResponse{Request: playbookRequest(r)}, nil
}

func playbookRequest(r signals.PlaybookRequest) *pantherclawv1.IdentityPlaybookRequest {
	out := &pantherclawv1.IdentityPlaybookRequest{
		Id: r.ID.String(), Kind: r.Kind, Events: r.Events, BaseVersion: int32(r.BaseVersion), //nolint:gosec // G115: a small counter
		Required: int32(r.Required), State: r.State, RequestedBy: r.RequestedBy.String(), //nolint:gosec // G115: 1 or 2
		CreateTime: timestamppb.New(r.CreatedAt), ExpireTime: timestamppb.New(r.ExpiresAt), DecideTime: ts(r.DecidedAt),
		DecidedReason: r.DecidedReason, ConfirmUrl: r.URL,
	}
	for _, c := range r.Confirmations {
		out.Confirmations = append(out.Confirmations, &pantherclawv1.IdentityPlaybookConfirmation{
			PrincipalId: c.Principal.String(), CredentialId: c.Credential.String(), CreateTime: timestamppb.New(c.At),
		})
	}
	return out
}
