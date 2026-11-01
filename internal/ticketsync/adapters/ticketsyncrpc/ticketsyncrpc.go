// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ticketsyncrpc serves TicketSyncService (G0 M20 D255, D264) over
// the ticket sync use cases.
package ticketsyncrpc

import (
	"context"
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
	"github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// WebhookPath is the inbound route's prefix: the ticket system posts to
// <public URL>/webhooks/tickets/<org>/<config>.
const WebhookPath = "/webhooks/tickets/"

// Handler implements TicketSyncService.
type Handler struct {
	pantherclawv1connect.UnimplementedTicketSyncServiceHandler
	svc       *tsapp.Service
	publicURL string
}

// New returns the handler; publicURL makes the webhook URL.
func New(svc *tsapp.Service, publicURL string) *Handler {
	return &Handler{svc: svc, publicURL: strings.TrimSuffix(publicURL, "/")}
}

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func (h *Handler) config(ctx context.Context, c tsapp.Config) (*pantherclawv1.TicketSyncConfig, error) {
	org, err := orgOf(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TicketSyncConfig{
		Id: c.ID.String(), ConnectionId: c.Connection.String(), System: string(c.System), ProjectKey: c.ProjectKey, State: c.State,
		CreateTime: timestamppb.New(c.Created), WebhookUrl: h.publicURL + WebhookPath + org.String() + "/" + c.ID.String(),
	}, nil
}

func refProto(r tsapp.Ref) *pantherclawv1.TicketRef {
	out := &pantherclawv1.TicketRef{Id: r.ID.String(), System: string(r.System), Key: r.Key}
	if r.Case != nil {
		out.CaseId = r.Case.String()
	}
	if r.Incident != nil {
		out.IncidentId = r.Incident.String()
	}
	return out
}

// CreateTicketSyncConfig implements TicketSyncService.
func (h *Handler) CreateTicketSyncConfig(ctx context.Context, req *pantherclawv1.CreateTicketSyncConfigRequest) (*pantherclawv1.CreateTicketSyncConfigResponse, error) {
	conn, err := idOf(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	c, secret, err := h.svc.CreateConfig(ctx, conn, req.GetProjectKey())
	if err != nil {
		return nil, err
	}
	pc, err := h.config(ctx, c)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateTicketSyncConfigResponse{Config: pc, WebhookSecret: string(secret)}, nil
}

// ListTicketSyncConfigs implements TicketSyncService.
func (h *Handler) ListTicketSyncConfigs(ctx context.Context, _ *pantherclawv1.ListTicketSyncConfigsRequest) (*pantherclawv1.ListTicketSyncConfigsResponse, error) {
	cs, err := h.svc.Configs(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTicketSyncConfigsResponse{}
	for _, c := range cs {
		pc, err := h.config(ctx, c)
		if err != nil {
			return nil, err
		}
		out.Configs = append(out.Configs, pc)
	}
	return out, nil
}

// RotateTicketSyncSecret implements TicketSyncService.
func (h *Handler) RotateTicketSyncSecret(ctx context.Context, req *pantherclawv1.RotateTicketSyncSecretRequest) (*pantherclawv1.RotateTicketSyncSecretResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	secret, err := h.svc.RotateSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateTicketSyncSecretResponse{WebhookSecret: string(secret)}, nil
}

// SetTicketSyncPaused implements TicketSyncService.
func (h *Handler) SetTicketSyncPaused(ctx context.Context, req *pantherclawv1.SetTicketSyncPausedRequest) (*pantherclawv1.SetTicketSyncPausedResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetTicketSyncPausedResponse{}, h.svc.SetPaused(ctx, id, req.GetPaused())
}

// LinkCaseTicket implements TicketSyncService.
func (h *Handler) LinkCaseTicket(ctx context.Context, req *pantherclawv1.LinkCaseTicketRequest) (*pantherclawv1.LinkCaseTicketResponse, error) {
	c, err := idOf(req.GetCaseId())
	if err != nil {
		return nil, err
	}
	cfg, err := idOf(req.GetConfigId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.LinkCase(ctx, c, cfg, req.GetKey())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.LinkCaseTicketResponse{Ref: refProto(r)}, nil
}

// LinkIncidentTicket implements TicketSyncService.
func (h *Handler) LinkIncidentTicket(ctx context.Context, req *pantherclawv1.LinkIncidentTicketRequest) (*pantherclawv1.LinkIncidentTicketResponse, error) {
	i, err := idOf(req.GetIncidentId())
	if err != nil {
		return nil, err
	}
	cfg, err := idOf(req.GetConfigId())
	if err != nil {
		return nil, err
	}
	r, err := h.svc.LinkIncident(ctx, i, cfg, req.GetKey())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.LinkIncidentTicketResponse{Ref: refProto(r)}, nil
}

// OpenCaseTicket implements TicketSyncService.
func (h *Handler) OpenCaseTicket(ctx context.Context, req *pantherclawv1.OpenCaseTicketRequest) (*pantherclawv1.OpenCaseTicketResponse, error) {
	c, err := idOf(req.GetCaseId())
	if err != nil {
		return nil, err
	}
	cfg, err := idOf(req.GetConfigId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.OpenCaseTicket(ctx, c, cfg)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.OpenCaseTicketResponse{OutboundId: out.String()}, nil
}

// OpenIncidentTicket implements TicketSyncService.
func (h *Handler) OpenIncidentTicket(ctx context.Context, req *pantherclawv1.OpenIncidentTicketRequest) (*pantherclawv1.OpenIncidentTicketResponse, error) {
	i, err := idOf(req.GetIncidentId())
	if err != nil {
		return nil, err
	}
	cfg, err := idOf(req.GetConfigId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.OpenIncidentTicket(ctx, i, cfg)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.OpenIncidentTicketResponse{OutboundId: out.String()}, nil
}

// GetTicketFieldOwners implements TicketSyncService.
func (h *Handler) GetTicketFieldOwners(ctx context.Context, _ *pantherclawv1.GetTicketFieldOwnersRequest) (*pantherclawv1.GetTicketFieldOwnersResponse, error) {
	own, err := h.svc.FieldOwners(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetTicketFieldOwnersResponse{}
	for _, f := range domain.Fields {
		out.Owners = append(out.Owners, &pantherclawv1.TicketFieldOwner{Field: string(f), Owner: string(own.Of(f)), Movable: f.Movable()})
	}
	return out, nil
}

// SetTicketFieldOwner implements TicketSyncService.
func (h *Handler) SetTicketFieldOwner(ctx context.Context, req *pantherclawv1.SetTicketFieldOwnerRequest) (*pantherclawv1.SetTicketFieldOwnerResponse, error) {
	return &pantherclawv1.SetTicketFieldOwnerResponse{}, h.svc.SetFieldOwner(ctx, domain.Field(req.GetField()), domain.Owner(req.GetOwner()))
}

// ListTicketRefs implements TicketSyncService.
func (h *Handler) ListTicketRefs(ctx context.Context, req *pantherclawv1.ListTicketRefsRequest) (*pantherclawv1.ListTicketRefsResponse, error) {
	var refs []tsapp.Ref
	if raw := req.GetIncidentId(); raw != "" {
		id, err := idOf(raw)
		if err != nil {
			return nil, err
		}
		if refs, err = h.svc.RefsOfIncident(ctx, id); err != nil {
			return nil, err
		}
	} else {
		id, err := idOf(req.GetCaseId())
		if err != nil {
			return nil, err
		}
		if refs, err = h.svc.RefsOfCase(ctx, id); err != nil {
			return nil, err
		}
	}
	out := &pantherclawv1.ListTicketRefsResponse{}
	for _, r := range refs {
		out.Refs = append(out.Refs, refProto(r))
	}
	return out, nil
}

// ListTicketSyncEvents implements TicketSyncService.
func (h *Handler) ListTicketSyncEvents(ctx context.Context, req *pantherclawv1.ListTicketSyncEventsRequest) (*pantherclawv1.ListTicketSyncEventsResponse, error) {
	config, err := idOf(req.GetConfigId())
	if err != nil {
		return nil, err
	}
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	events, next, err := h.svc.SyncEvents(ctx, config, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTicketSyncEventsResponse{NextPageToken: next}
	for _, e := range events {
		out.Events = append(out.Events, &pantherclawv1.TicketSyncEvent{
			Id: e.ID.String(), Direction: e.Direction, OccurTime: timestamppb.New(e.OccurredAt), Status: e.Status, IssueKey: e.IssueKey,
			Action: e.Action, CaseId: e.CaseID, IncidentId: e.IncidentID, ResultCode: e.ResultCode,
		})
	}
	return out, nil
}
