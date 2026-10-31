// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package catalogrpc serves McpCatalogService over Connect (G0 M24 D222).
package catalogrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/app"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves McpCatalogService.
type Handler struct {
	pantherclawv1connect.UnimplementedMcpCatalogServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var statusOf = map[string]pantherclawv1.McpServerStatus{
	string(domain.StatusProposed): pantherclawv1.McpServerStatus_MCP_SERVER_STATUS_PROPOSED,
	string(domain.StatusApproved): pantherclawv1.McpServerStatus_MCP_SERVER_STATUS_APPROVED,
	string(domain.StatusDenied):   pantherclawv1.McpServerStatus_MCP_SERVER_STATUS_DENIED,
	string(domain.StatusRevoked):  pantherclawv1.McpServerStatus_MCP_SERVER_STATUS_REVOKED,
}

var transportOf = map[string]pantherclawv1.McpServerTransport{
	domain.TransportHTTP:      pantherclawv1.McpServerTransport_MCP_SERVER_TRANSPORT_HTTP,
	domain.TransportStdio:     pantherclawv1.McpServerTransport_MCP_SERVER_TRANSPORT_STDIO,
	domain.TransportContainer: pantherclawv1.McpServerTransport_MCP_SERVER_TRANSPORT_CONTAINER,
}

var modeOf = map[string]pantherclawv1.McpCatalogMode{
	string(domain.ModeOff):     pantherclawv1.McpCatalogMode_MCP_CATALOG_MODE_OFF,
	string(domain.ModeWatch):   pantherclawv1.McpCatalogMode_MCP_CATALOG_MODE_WATCH,
	string(domain.ModeEnforce): pantherclawv1.McpCatalogMode_MCP_CATALOG_MODE_ENFORCE,
}

// server is an entry as the API shows it.
func server(r dbq.PcMcpServer) *pantherclawv1.McpServer {
	return &pantherclawv1.McpServer{
		Id: r.ID.String(), Name: r.Name, Title: r.Title, Status: statusOf[r.Status], Transport: transportOf[r.Transport],
		PackageRef: deref(r.PackageRef), UrlHost: deref(r.UrlHost), UrlPathPrefix: deref(r.UrlPathPrefix), ImageDigest: deref(r.ImageDigest),
		Notes: r.Notes, DecidedBy: deref(r.DecidedBy), DecideTime: tsp(r.DecidedAt), CreateTime: timestamppb.New(r.CreatedAt),
	}
}

func settings(r dbq.PcMcpCatalogSetting) *pantherclawv1.McpCatalogSettings {
	return &pantherclawv1.McpCatalogSettings{Mode: modeOf[r.Mode], UpdatedBy: deref(r.UpdatedBy), UpdateTime: tsp(&r.UpdatedAt)}
}

// ProposeServer implements McpCatalogServiceHandler.
func (h *Handler) ProposeServer(ctx context.Context, req *pantherclawv1.ProposeServerRequest) (*pantherclawv1.ProposeServerResponse, error) {
	var transport string
	for k, v := range transportOf {
		if v == req.GetTransport() {
			transport = k
		}
	}
	r, err := h.s.Propose(ctx, domain.Proposal{
		Name: req.GetName(), Title: req.GetTitle(), Transport: transport, Notes: req.GetNotes(),
		Spec: domain.Spec{
			Host: req.GetUrlHost(), PathPrefix: req.GetUrlPathPrefix(), ImageDigest: req.GetImageDigest(), PackageRef: req.GetPackageRef(),
		},
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ProposeServerResponse{Server: server(r)}, nil
}

// ApproveServer implements McpCatalogServiceHandler.
func (h *Handler) ApproveServer(ctx context.Context, req *pantherclawv1.ApproveServerRequest) (*pantherclawv1.ApproveServerResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.Approve(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ApproveServerResponse{Server: server(r)}, nil
}

// DenyServer implements McpCatalogServiceHandler.
func (h *Handler) DenyServer(ctx context.Context, req *pantherclawv1.DenyServerRequest) (*pantherclawv1.DenyServerResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.Deny(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DenyServerResponse{Server: server(r)}, nil
}

// ListServers implements McpCatalogServiceHandler.
func (h *Handler) ListServers(ctx context.Context, req *pantherclawv1.ListServersRequest) (*pantherclawv1.ListServersResponse, error) {
	var statuses []string
	for _, want := range req.GetStatuses() {
		for k, v := range statusOf {
			if v == want {
				statuses = append(statuses, k)
			}
		}
	}
	rows, next, err := h.s.List(ctx, req.GetPageSize(), req.GetPageToken(), statuses)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListServersResponse{NextPageToken: next}
	for _, r := range rows {
		out.Servers = append(out.Servers, server(r))
	}
	return out, nil
}

// GetServer implements McpCatalogServiceHandler.
func (h *Handler) GetServer(ctx context.Context, req *pantherclawv1.GetServerRequest) (*pantherclawv1.GetServerResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetServerResponse{Server: server(r)}, nil
}

// GetCatalogSettings implements McpCatalogServiceHandler.
func (h *Handler) GetCatalogSettings(ctx context.Context, _ *pantherclawv1.GetCatalogSettingsRequest) (*pantherclawv1.GetCatalogSettingsResponse, error) {
	r, err := h.s.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetCatalogSettingsResponse{Settings: settings(r)}, nil
}

func modeFrom(m pantherclawv1.McpCatalogMode) domain.Mode {
	for k, v := range modeOf {
		if v == m {
			return domain.Mode(k)
		}
	}
	return ""
}

func connectionRef(c dbq.McpConnectionsRow) *pantherclawv1.McpConnectionRef {
	return &pantherclawv1.McpConnectionRef{Id: c.ID.String(), Name: c.Name, Kind: c.Kind, State: c.State, GatewayId: c.GatewayID.String()}
}

// PreviewCatalogMode implements McpCatalogServiceHandler.
func (h *Handler) PreviewCatalogMode(ctx context.Context, req *pantherclawv1.PreviewCatalogModeRequest) (*pantherclawv1.PreviewCatalogModeResponse, error) {
	p, err := h.s.PreviewMode(ctx, modeFrom(req.GetMode()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.PreviewCatalogModeResponse{
		FromMode: modeOf[string(p.From)], ToMode: modeOf[string(p.To)], NeedsSecondPerson: p.SecondPerson, PreviewDigest: p.Digest,
	}
	for _, c := range p.Quarantines {
		out.Quarantines = append(out.Quarantines, connectionRef(c))
	}
	return out, nil
}

// SetCatalogMode implements McpCatalogServiceHandler.
func (h *Handler) SetCatalogMode(ctx context.Context, req *pantherclawv1.SetCatalogModeRequest) (*pantherclawv1.SetCatalogModeResponse, error) {
	r, err := h.s.SetMode(ctx, modeFrom(req.GetMode()), req.GetPreviewDigest(), req.GetReason())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SetCatalogModeResponse{Settings: settings(r.Settings)}
	for _, id := range r.Quarantined {
		out.QuarantinedConnectionIds = append(out.QuarantinedConnectionIds, id.String())
	}
	if r.Held != nil {
		out.Change = &pantherclawv1.ProtectedChangeFiled{ProtectedChangeId: r.Held.Change.String(), ChangeRequestId: r.Held.Request.String()}
	}
	return out, nil
}
