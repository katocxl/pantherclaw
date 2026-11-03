// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package provisioningrpc serves ProvisioningService over Connect (G0 M26
// D405, D406, D409). Every write but a revoke files a protected change and
// returns it; nothing here applies one. A token's secret goes out once, in
// CreateScimToken's answer.
package provisioningrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/provisioning/app"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Handler serves ProvisioningService.
type Handler struct {
	pantherclawv1connect.UnimplementedProvisioningServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

var (
	errInvalidID    = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")
	errInvalidToken = pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "invalid page token")
)

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

func filed(f app.Filed) *pantherclawv1.ProtectedChangeFiled {
	out := &pantherclawv1.ProtectedChangeFiled{ProtectedChangeId: f.Change.String(), ChangeRequestId: f.Request.String()}
	for _, u := range f.Stranded {
		out.StrandedAdminIds = append(out.StrandedAdminIds, u.String())
	}
	return out
}

func tokenProto(t app.Token) *pantherclawv1.ScimToken {
	return &pantherclawv1.ScimToken{
		Id: t.ID.String(), Name: t.Name, Issuer: t.Issuer, SubjectAttribute: t.SubjectAttribute, Hint: t.Hint, State: t.State,
		CreatedBy: t.CreatedBy, CreateTime: timestamppb.New(t.CreatedAt), ExpireTime: timestamppb.New(t.ExpiresAt),
		ActivateTime: tsp(t.ActivatedAt), RevokeTime: tsp(t.RevokedAt), LastUseTime: tsp(t.LastUsedAt),
	}
}

func connectionProto(c app.Connection) *pantherclawv1.SamlConnection {
	return &pantherclawv1.SamlConnection{
		Id: c.ID.String(), Name: c.Name, IdpEntityId: c.EntityID, Issuer: c.Issuer, SsoUrl: c.SSOURL, Certificates: c.Certificates,
		State: c.State, CreatedBy: c.CreatedBy, CreateTime: timestamppb.New(c.CreatedAt), UpdateTime: timestamppb.New(c.UpdatedAt),
		ActivateTime: tsp(c.ActivatedAt), DisableTime: tsp(c.DisabledAt),
	}
}

// CreateScimToken implements ProvisioningServiceHandler.
func (h *Handler) CreateScimToken(ctx context.Context, req *pantherclawv1.CreateScimTokenRequest) (*pantherclawv1.CreateScimTokenResponse, error) {
	t, secret, f, err := h.s.CreateToken(ctx, app.TokenInput{
		Name: req.GetName(), Issuer: req.GetIssuer(), SubjectAttribute: req.GetSubjectAttribute(), TTLDays: int(req.GetTtlDays()),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateScimTokenResponse{Token: tokenProto(t), Secret: secret, Filed: filed(f)}, nil
}

// RevokeScimToken implements ProvisioningServiceHandler.
func (h *Handler) RevokeScimToken(ctx context.Context, req *pantherclawv1.RevokeScimTokenRequest) (*pantherclawv1.RevokeScimTokenResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := h.s.RevokeToken(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeScimTokenResponse{Token: tokenProto(t)}, nil
}

// ListScimTokens implements ProvisioningServiceHandler.
func (h *Handler) ListScimTokens(ctx context.Context, _ *pantherclawv1.ListScimTokensRequest) (*pantherclawv1.ListScimTokensResponse, error) {
	ts, err := h.s.ListTokens(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListScimTokensResponse{}
	for _, t := range ts {
		out.Tokens = append(out.Tokens, tokenProto(t))
	}
	return out, nil
}

// CreateSamlConnection implements ProvisioningServiceHandler.
func (h *Handler) CreateSamlConnection(ctx context.Context, req *pantherclawv1.CreateSamlConnectionRequest) (
	*pantherclawv1.CreateSamlConnectionResponse, error,
) {
	c, f, err := h.s.CreateConnection(ctx, domain.Connection{
		Name: req.GetName(), EntityID: req.GetIdpEntityId(), SSOURL: req.GetSsoUrl(), Certificates: req.GetCertificates(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateSamlConnectionResponse{Connection: connectionProto(c), Filed: filed(f)}, nil
}

// UpdateSamlConnection implements ProvisioningServiceHandler.
func (h *Handler) UpdateSamlConnection(ctx context.Context, req *pantherclawv1.UpdateSamlConnectionRequest) (
	*pantherclawv1.UpdateSamlConnectionResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.s.UpdateConnection(ctx, id, req.GetSsoUrl(), req.GetCertificates())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateSamlConnectionResponse{Filed: filed(f)}, nil
}

// DisableSamlConnection implements ProvisioningServiceHandler.
func (h *Handler) DisableSamlConnection(ctx context.Context, req *pantherclawv1.DisableSamlConnectionRequest) (
	*pantherclawv1.DisableSamlConnectionResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.s.DisableConnection(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableSamlConnectionResponse{Filed: filed(f)}, nil
}

// ListSamlConnections implements ProvisioningServiceHandler.
func (h *Handler) ListSamlConnections(ctx context.Context, _ *pantherclawv1.ListSamlConnectionsRequest) (
	*pantherclawv1.ListSamlConnectionsResponse, error,
) {
	cs, err := h.s.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSamlConnectionsResponse{}
	for _, c := range cs {
		out.Connections = append(out.Connections, connectionProto(c))
	}
	return out, nil
}

// ListGroups implements ProvisioningServiceHandler. The page token is the
// last group's id.
func (h *Handler) ListGroups(ctx context.Context, req *pantherclawv1.ListGroupsRequest) (*pantherclawv1.ListGroupsResponse, error) {
	var after ids.UUID
	if t := req.GetPageToken(); t != "" {
		var err error
		if after, err = ids.ParseUUID(t); err != nil {
			return nil, errInvalidToken
		}
	}
	size := int(req.GetPageSize())
	if size <= 0 {
		size = 100
	}
	gs, err := h.s.DirectoryGroups(ctx, after, size+1)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListGroupsResponse{}
	if len(gs) > size {
		gs = gs[:size]
		out.NextPageToken = gs[size-1].ID.String()
	}
	for _, g := range gs {
		out.Groups = append(out.Groups, &pantherclawv1.DirectoryGroup{
			Id: g.ID.String(), Issuer: g.Issuer, DisplayName: g.DisplayName, MemberCount: g.MemberCount,
		})
	}
	return out, nil
}

// ListGroupRoleMappings implements ProvisioningServiceHandler.
func (h *Handler) ListGroupRoleMappings(ctx context.Context, _ *pantherclawv1.ListGroupRoleMappingsRequest) (
	*pantherclawv1.ListGroupRoleMappingsResponse, error,
) {
	ms, err := h.s.ListMappings(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListGroupRoleMappingsResponse{}
	for _, m := range ms {
		p := &pantherclawv1.GroupRoleMapping{
			Id: m.ID.String(), GroupId: m.Group.String(), Role: string(m.Role), ScopeType: string(m.Scope.Type),
			CreatedBy: m.CreatedBy, CreateTime: timestamppb.New(m.CreatedAt),
		}
		if m.Scope.Type != td.ScopeOrg {
			p.ScopeId = m.Scope.ID.String()
		}
		out.Mappings = append(out.Mappings, p)
	}
	return out, nil
}

// AddGroupRoleMapping implements ProvisioningServiceHandler.
func (h *Handler) AddGroupRoleMapping(ctx context.Context, req *pantherclawv1.AddGroupRoleMappingRequest) (
	*pantherclawv1.AddGroupRoleMappingResponse, error,
) {
	group, err := idOf(req.GetGroupId())
	if err != nil {
		return nil, err
	}
	scope := td.Scope{Type: td.ScopeType(req.GetScopeType())}
	if scope.Type != td.ScopeOrg {
		if scope.ID, err = idOf(req.GetScopeId()); err != nil {
			return nil, err
		}
	} else if req.GetScopeId() != "" {
		return nil, errInvalidID
	}
	f, err := h.s.AddMapping(ctx, group, td.RoleName(req.GetRole()), scope)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddGroupRoleMappingResponse{Filed: filed(f)}, nil
}

// RemoveGroupRoleMapping implements ProvisioningServiceHandler.
func (h *Handler) RemoveGroupRoleMapping(ctx context.Context, req *pantherclawv1.RemoveGroupRoleMappingRequest) (
	*pantherclawv1.RemoveGroupRoleMappingResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.s.RemoveMapping(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveGroupRoleMappingResponse{Filed: filed(f)}, nil
}
