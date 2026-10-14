// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package connectionsrpc serves ConnectionService (G0 M6): connections and
// their route modes, and credential custody (sealing keys, sealed uploads,
// metadata and revocation). No procedure returns sealed bytes (HR-061).
package connectionsrpc

import (
	"context"
	"encoding/json/v2"

	"google.golang.org/protobuf/types/known/timestamppb"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// Handler serves ConnectionService.
type Handler struct {
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	s     *capp.Service
	creds *credapp.Service
}

// New returns the ConnectionService handler.
func New(s *capp.Service, creds *credapp.Service) *Handler { return &Handler{s: s, creds: creds} }

var _ pantherclawv1connect.ConnectionServiceHandler = (*Handler)(nil)

var (
	kinds = map[pb.ConnectionKind]string{
		pb.ConnectionKind_CONNECTION_KIND_HTTP: capp.KindHTTP, pb.ConnectionKind_CONNECTION_KIND_MCP: capp.KindMCP,
		pb.ConnectionKind_CONNECTION_KIND_LOCAL: capp.KindLocal, pb.ConnectionKind_CONNECTION_KIND_MCP_CONTAINER: capp.KindMCPContainer,
	}
	modes = map[pb.RouteMode]string{
		pb.RouteMode_ROUTE_MODE_MONITOR: capp.ModeMonitor, pb.RouteMode_ROUTE_MODE_ENFORCE: capp.ModeEnforce,
	}
	access = map[pb.AccessMode]string{
		pb.AccessMode_ACCESS_MODE_PANTHERCLAW_HELD: capp.AccessHeld, pb.AccessMode_ACCESS_MODE_AGENT_HELD: capp.AccessAgentHeld,
		pb.AccessMode_ACCESS_MODE_TARGET_ENFORCED: capp.AccessTargetEnforced, pb.AccessMode_ACCESS_MODE_NONE: capp.AccessNone,
	}
	classes = map[pb.DestinationClass]string{
		pb.DestinationClass_DESTINATION_CLASS_PUBLIC: capp.ClassPublic, pb.DestinationClass_DESTINATION_CLASS_INTERNAL: capp.ClassInternal,
	}
	states = map[string]pb.ConnectionState{
		capp.StateActive: pb.ConnectionState_CONNECTION_STATE_ACTIVE, capp.StateQuarantined: pb.ConnectionState_CONNECTION_STATE_QUARANTINED,
		capp.StateRetired: pb.ConnectionState_CONNECTION_STATE_RETIRED,
	}
)

func invert[K, V comparable](m map[K]V) map[V]K {
	out := make(map[V]K, len(m))
	for k, v := range m {
		out[v] = k
	}
	return out
}

var (
	kindOf   = invert(kinds)
	modeOf   = invert(modes)
	accessOf = invert(access)
	classOf  = invert(classes)
)

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func connectionOf(c capp.Connection) *pb.Connection {
	out := &pb.Connection{
		Id: c.ID.String(), Name: c.Name, Kind: kindOf[c.Kind], GatewayId: c.GatewayID.String(), Package: c.Package,
		BaseUrl: deref(c.BaseUrl), AllowedHosts: c.AllowedHosts, DestinationClass: classOf[c.DestinationClass],
		AccessMode: accessOf[c.AccessMode], CredentialHeader: deref(c.CredentialHeader), CredentialScheme: deref(c.CredentialScheme),
		DefaultMode: modeOf[c.DefaultMode], MaxResponseBytes: c.MaxResponseBytes, TimeoutMs: c.TimeoutMs, State: states[c.State],
		QuarantineReason: deref(c.QuarantineReason), Revision: c.Revision, CreatedBy: c.CreatedBy,
		CreateTime: timestamppb.New(c.CreatedAt), UpdatedBy: c.UpdatedBy, UpdateTime: timestamppb.New(c.UpdatedAt), AgentHosts: c.AgentHosts,
		Connector: connectorOf(c.Connector),
	}
	for _, r := range c.Routes {
		out.Routes = append(out.Routes, routeOf(r))
	}
	if c.GitHub != nil {
		out.Github = githubOf(*c.GitHub)
	}
	return out
}

// githubOf renders a connection's GitHub App installation; what was read
// from GitHub comes with the time it was read.
func githubOf(g dbq.PcConnectionGithub) *pb.GitHubInstallation {
	out := &pb.GitHubInstallation{
		AppClientId: g.AppClientID, InstallationId: g.InstallationID, AccountLogin: g.AccountLogin, AccountId: g.AccountID.Int64,
		RepositorySelection: deref(g.RepositorySelection),
	}
	if g.ReadAt != nil {
		out.ReadTime = timestamppb.New(*g.ReadAt)
	}
	_ = json.Unmarshal(g.Permissions, &out.Permissions) // a jsonb object of strings; anything else reads as none
	return out
}

func routeOf(r dbq.PcConnectionRoute) *pb.ConnectionRoute {
	return &pb.ConnectionRoute{Route: r.Route, Mode: modeOf[r.Mode], ChangedBy: r.ChangedBy, ChangeTime: timestamppb.New(r.ChangedAt)}
}

func parseID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

// CreateConnection implements ConnectionServiceHandler.
func (h *Handler) CreateConnection(ctx context.Context, req *pb.CreateConnectionRequest) (*pb.CreateConnectionResponse, error) {
	gw, err := parseID(req.GetGatewayId())
	if err != nil {
		return nil, err
	}
	spec, err := specIn(req.GetConnector())
	if err != nil {
		return nil, err
	}
	c, err := h.s.Create(ctx, capp.CreateInput{
		Name: req.GetName(), Kind: kinds[req.GetKind()], Package: req.GetPackage(), BaseURL: req.GetBaseUrl(), Gateway: gw,
		AllowedHosts: req.GetAllowedHosts(), DestinationClass: classes[req.GetDestinationClass()], AccessMode: access[req.GetAccessMode()],
		CredentialHeader: req.GetCredentialHeader(), CredentialScheme: req.GetCredentialScheme(), DefaultMode: modes[req.GetDefaultMode()],
		MaxResponseBytes: req.GetMaxResponseBytes(), TimeoutMs: req.GetTimeoutMs(), AgentHosts: req.GetAgentHosts(),
		Connector: spec,
	})
	if err != nil {
		return nil, err
	}
	return &pb.CreateConnectionResponse{Connection: connectionOf(c)}, nil
}

// GetConnection implements ConnectionServiceHandler.
func (h *Handler) GetConnection(ctx context.Context, req *pb.GetConnectionRequest) (*pb.GetConnectionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.GetConnectionResponse{Connection: connectionOf(c)}
	if out.ActiveCredential, err = h.activeCredential(ctx, out.Connection); err != nil {
		return nil, err
	}
	return out, nil
}

// ListConnections implements ConnectionServiceHandler.
func (h *Handler) ListConnections(ctx context.Context, req *pb.ListConnectionsRequest) (*pb.ListConnectionsResponse, error) {
	var gw *ids.UUID
	if req.GetGatewayId() != "" {
		id, err := parseID(req.GetGatewayId())
		if err != nil {
			return nil, err
		}
		gw = &id
	}
	rows, next, err := h.s.List(ctx, req.GetPageSize(), req.GetPageToken(), gw, req.GetIncludeRetired())
	if err != nil {
		return nil, err
	}
	out := &pb.ListConnectionsResponse{NextPageToken: next}
	for _, c := range rows {
		out.Connections = append(out.Connections, connectionOf(c))
	}
	return out, nil
}

// UpdateConnection implements ConnectionServiceHandler.
func (h *Handler) UpdateConnection(ctx context.Context, req *pb.UpdateConnectionRequest) (*pb.UpdateConnectionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	in := capp.UpdateInput{
		ID: id, Revision: req.GetRevision(), BaseURL: req.BaseUrl, AllowedHosts: req.GetAllowedHosts(),
		SetAllowedHosts: req.GetUpdateAllowedHosts(), MaxResponseBytes: req.MaxResponseBytes, TimeoutMs: req.TimeoutMs,
		AgentHosts: req.GetAgentHosts(), SetAgentHosts: req.GetUpdateAgentHosts(),
	}
	if in.Connector, err = specIn(req.GetConnector()); err != nil {
		return nil, err
	}
	if req.GatewayId != nil {
		gw, err := parseID(req.GetGatewayId())
		if err != nil {
			return nil, err
		}
		in.Gateway = &gw
	}
	if req.DestinationClass != nil {
		v := classes[req.GetDestinationClass()]
		in.DestinationClass = &v
	}
	if req.AccessMode != nil {
		v := access[req.GetAccessMode()]
		in.AccessMode = &v
	}
	if req.DefaultMode != nil {
		v := modes[req.GetDefaultMode()]
		in.DefaultMode = &v
	}
	c, err := h.s.Update(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pb.UpdateConnectionResponse{Connection: connectionOf(c)}, nil
}

// SetRouteMode implements ConnectionServiceHandler.
func (h *Handler) SetRouteMode(ctx context.Context, req *pb.SetRouteModeRequest) (*pb.SetRouteModeResponse, error) {
	id, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.SetRouteMode(ctx, id, req.GetRoute(), modes[req.GetMode()])
	if err != nil {
		return nil, err
	}
	return &pb.SetRouteModeResponse{Connection: connectionOf(c)}, nil
}

// QuarantineConnection implements ConnectionServiceHandler.
func (h *Handler) QuarantineConnection(ctx context.Context, req *pb.QuarantineConnectionRequest) (*pb.QuarantineConnectionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.Quarantine(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.QuarantineConnectionResponse{Connection: connectionOf(c)}, nil
}

// RestoreConnection implements ConnectionServiceHandler.
func (h *Handler) RestoreConnection(ctx context.Context, req *pb.RestoreConnectionRequest) (*pb.RestoreConnectionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	c, err := h.s.Restore(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pb.RestoreConnectionResponse{Connection: connectionOf(c)}, nil
}

// RetireConnection implements ConnectionServiceHandler.
func (h *Handler) RetireConnection(ctx context.Context, req *pb.RetireConnectionRequest) (*pb.RetireConnectionResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	if err := h.s.Retire(ctx, id); err != nil {
		return nil, err
	}
	return &pb.RetireConnectionResponse{}, nil
}
