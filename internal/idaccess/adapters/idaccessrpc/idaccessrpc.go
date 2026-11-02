// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package idaccessrpc serves IdpAccessService over Connect (G0 M26 D400,
// D402, D408). Every addition files a protected change and returns its
// request; every removal applies at once.
package idaccessrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/idaccess/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves IdpAccessService.
type Handler struct {
	pantherclawv1connect.UnimplementedIdpAccessServiceHandler
	s *app.Admin
}

// New returns the handler.
func New(s *app.Admin) *Handler { return &Handler{s: s} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil || id.IsZero() {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func issuer(r dbq.PcOrgAssertionIssuer) *pantherclawv1.AssertionIssuer {
	out := &pantherclawv1.AssertionIssuer{
		Id: r.ID.String(), Name: r.Name, Issuer: r.Issuer, Audience: r.Audience, Algorithms: r.Algorithms, State: r.State,
		CreateTime: timestamppb.New(r.CreatedAt), ActivateTime: tsp(r.ActivatedAt),
	}
	if r.Tenant != nil {
		out.Tenant = *r.Tenant
	}
	return out
}

func client(r dbq.PcOrgAssertionClient) *pantherclawv1.AssertionClient {
	return &pantherclawv1.AssertionClient{
		Id: r.ID.String(), IssuerId: r.IssuerID.String(), ClientId: r.ClientID, AgentId: r.AgentID.String(), State: r.State,
		CreateTime: timestamppb.New(r.CreatedAt),
	}
}

func mcpClient(r dbq.PcMcpClient) *pantherclawv1.McpClient {
	return &pantherclawv1.McpClient{
		Id: r.ID.String(), ClientUrl: r.ClientUrl, AgentId: r.AgentID.String(), InstanceId: r.InstanceID.String(), State: r.State,
		CreateTime: timestamppb.New(r.CreatedAt),
	}
}

func access(a app.McpAccess) *pantherclawv1.McpAccess {
	return &pantherclawv1.McpAccess{Enabled: a.Enabled, GatewayUrl: a.GatewayURL, Issuer: a.Issuer}
}

// CreateAssertionIssuer implements IdpAccessServiceHandler.
func (h *Handler) CreateAssertionIssuer(ctx context.Context, req *pantherclawv1.CreateAssertionIssuerRequest) (
	*pantherclawv1.CreateAssertionIssuerResponse, error,
) {
	r, f, err := h.s.CreateIssuer(ctx, app.IssuerInput{
		Name: req.GetName(), Issuer: req.GetIssuer(), Tenant: req.GetTenant(), Algorithms: req.GetAlgorithms(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateAssertionIssuerResponse{Issuer: issuer(r), RequestId: f.Request.String()}, nil
}

// DisableAssertionIssuer implements IdpAccessServiceHandler.
func (h *Handler) DisableAssertionIssuer(ctx context.Context, req *pantherclawv1.DisableAssertionIssuerRequest) (
	*pantherclawv1.DisableAssertionIssuerResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.DisableIssuer(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableAssertionIssuerResponse{Issuer: issuer(r)}, nil
}

// ListAssertionIssuers implements IdpAccessServiceHandler.
func (h *Handler) ListAssertionIssuers(ctx context.Context, _ *pantherclawv1.ListAssertionIssuersRequest) (
	*pantherclawv1.ListAssertionIssuersResponse, error,
) {
	rs, err := h.s.ListIssuers(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAssertionIssuersResponse{}
	for _, r := range rs {
		out.Issuers = append(out.Issuers, issuer(r))
	}
	return out, nil
}

// BindAssertionClient implements IdpAccessServiceHandler.
func (h *Handler) BindAssertionClient(ctx context.Context, req *pantherclawv1.BindAssertionClientRequest) (
	*pantherclawv1.BindAssertionClientResponse, error,
) {
	iss, err := idOf(req.GetIssuerId())
	if err != nil {
		return nil, err
	}
	agent, err := idOf(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	r, f, err := h.s.BindClient(ctx, iss, req.GetClientId(), agent)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.BindAssertionClientResponse{Client: client(r), RequestId: f.Request.String()}, nil
}

// RemoveAssertionClient implements IdpAccessServiceHandler.
func (h *Handler) RemoveAssertionClient(ctx context.Context, req *pantherclawv1.RemoveAssertionClientRequest) (
	*pantherclawv1.RemoveAssertionClientResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.RemoveClient(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveAssertionClientResponse{Client: client(r)}, nil
}

// ListAssertionClients implements IdpAccessServiceHandler.
func (h *Handler) ListAssertionClients(ctx context.Context, req *pantherclawv1.ListAssertionClientsRequest) (
	*pantherclawv1.ListAssertionClientsResponse, error,
) {
	iss, err := idOf(req.GetIssuerId())
	if err != nil {
		return nil, err
	}
	rs, err := h.s.ListClients(ctx, iss)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAssertionClientsResponse{}
	for _, r := range rs {
		out.Clients = append(out.Clients, client(r))
	}
	return out, nil
}

// GetMcpAccess implements IdpAccessServiceHandler.
func (h *Handler) GetMcpAccess(ctx context.Context, _ *pantherclawv1.GetMcpAccessRequest) (*pantherclawv1.GetMcpAccessResponse, error) {
	a, err := h.s.GetMcpAccess(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetMcpAccessResponse{Access: access(a)}, nil
}

// EnableMcpAccess implements IdpAccessServiceHandler.
func (h *Handler) EnableMcpAccess(ctx context.Context, req *pantherclawv1.EnableMcpAccessRequest) (
	*pantherclawv1.EnableMcpAccessResponse, error,
) {
	f, err := h.s.EnableMcpAccess(ctx, req.GetGatewayUrl())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.EnableMcpAccessResponse{RequestId: f.Request.String()}, nil
}

// DisableMcpAccess implements IdpAccessServiceHandler.
func (h *Handler) DisableMcpAccess(ctx context.Context, _ *pantherclawv1.DisableMcpAccessRequest) (
	*pantherclawv1.DisableMcpAccessResponse, error,
) {
	a, err := h.s.DisableMcpAccess(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableMcpAccessResponse{Access: access(a)}, nil
}

// AllowMcpClient implements IdpAccessServiceHandler.
func (h *Handler) AllowMcpClient(ctx context.Context, req *pantherclawv1.AllowMcpClientRequest) (*pantherclawv1.AllowMcpClientResponse, error) {
	agent, err := idOf(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	r, f, err := h.s.AllowMcpClient(ctx, req.GetClientUrl(), agent)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AllowMcpClientResponse{Client: mcpClient(r), RequestId: f.Request.String()}, nil
}

// RemoveMcpClient implements IdpAccessServiceHandler.
func (h *Handler) RemoveMcpClient(ctx context.Context, req *pantherclawv1.RemoveMcpClientRequest) (
	*pantherclawv1.RemoveMcpClientResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.RemoveMcpClient(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveMcpClientResponse{Client: mcpClient(r)}, nil
}

// ListMcpClients implements IdpAccessServiceHandler.
func (h *Handler) ListMcpClients(ctx context.Context, _ *pantherclawv1.ListMcpClientsRequest) (*pantherclawv1.ListMcpClientsResponse, error) {
	rs, err := h.s.ListMcpClients(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListMcpClientsResponse{}
	for _, r := range rs {
		out.Clients = append(out.Clients, mcpClient(r))
	}
	return out, nil
}
