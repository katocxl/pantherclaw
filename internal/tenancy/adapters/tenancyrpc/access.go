// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package tenancyrpc

import (
	"context"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Access serves AccessService.
type Access struct {
	pantherclawv1connect.UnimplementedAccessServiceHandler
	a *app.Access
	// deployment is what WhoAmI reports (whoami_ui.go).
	deployment pantherclawv1.Deployment
}

// NewAccess returns the AccessService handler.
func NewAccess(a *app.Access) *Access { return &Access{a: a} }

// WhoAmI implements AccessServiceHandler.
func (s *Access) WhoAmI(ctx context.Context, _ *pantherclawv1.WhoAmIRequest) (*pantherclawv1.WhoAmIResponse, error) {
	id, err := s.a.WhoAmI(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.WhoAmIResponse{
		Principal: &pantherclawv1.Principal{
			Type: principalTypeToProto[id.Principal.Kind], Id: id.Principal.ID.String(), DisplayName: id.DisplayName,
		},
		OrgId: id.Org.String(), OrgName: id.OrgName, Credential: string(id.Credential),
		Deployment: s.deployment, SessionKind: sessionKindOf(id.Credential),
	}
	for _, b := range id.Bindings {
		out.Bindings = append(out.Bindings, bindingProto(b))
	}
	for _, p := range id.Permissions() {
		out.Permissions = append(out.Permissions, string(p))
	}
	return out, nil
}

// ListUsers implements AccessServiceHandler.
func (s *Access) ListUsers(ctx context.Context, req *pantherclawv1.ListUsersRequest) (*pantherclawv1.ListUsersResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := s.a.ListUsers(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListUsersResponse{NextPageToken: p.Next}
	for _, u := range p.Items {
		out.Users = append(out.Users, userProto(u))
	}
	return out, nil
}

// GetUser implements AccessServiceHandler.
func (s *Access) GetUser(ctx context.Context, req *pantherclawv1.GetUserRequest) (*pantherclawv1.GetUserResponse, error) {
	id, err := parseID[td.User](req.GetId())
	if err != nil {
		return nil, err
	}
	u, err := s.a.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetUserResponse{User: userProto(u)}, nil
}

// SetUserState implements AccessServiceHandler.
func (s *Access) SetUserState(ctx context.Context, req *pantherclawv1.SetUserStateRequest) (*pantherclawv1.SetUserStateResponse, error) {
	id, err := parseID[td.User](req.GetId())
	if err != nil {
		return nil, err
	}
	u, err := s.a.SetUserState(ctx, id, accountStateFromProto[req.GetState()])
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetUserStateResponse{User: userProto(u)}, nil
}

// CreateInvitation implements AccessServiceHandler.
func (s *Access) CreateInvitation(ctx context.Context, req *pantherclawv1.CreateInvitationRequest) (*pantherclawv1.CreateInvitationResponse, error) {
	roles := make([]td.RoleName, len(req.GetRoles()))
	for i, r := range req.GetRoles() {
		roles[i] = td.RoleName(r)
	}
	inv, tok, err := s.a.CreateInvitation(ctx, req.GetEmail(), roles, time.Duration(req.GetTtlHours())*time.Hour)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateInvitationResponse{Invitation: invitationProto(inv), Token: tok.Reveal()}, nil
}

// ListInvitations implements AccessServiceHandler.
func (s *Access) ListInvitations(ctx context.Context, req *pantherclawv1.ListInvitationsRequest) (*pantherclawv1.ListInvitationsResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := s.a.ListInvitations(ctx, pr, req.GetIncludeClosed())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListInvitationsResponse{NextPageToken: p.Next}
	for _, i := range p.Items {
		out.Invitations = append(out.Invitations, invitationProto(i))
	}
	return out, nil
}

// RevokeInvitation implements AccessServiceHandler.
func (s *Access) RevokeInvitation(ctx context.Context, req *pantherclawv1.RevokeInvitationRequest) (*pantherclawv1.RevokeInvitationResponse, error) {
	id, err := parseID[td.Invitation](req.GetId())
	if err != nil {
		return nil, err
	}
	inv, err := s.a.RevokeInvitation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeInvitationResponse{Invitation: invitationProto(inv)}, nil
}

// ListRoles implements AccessServiceHandler.
func (s *Access) ListRoles(ctx context.Context, _ *pantherclawv1.ListRolesRequest) (*pantherclawv1.ListRolesResponse, error) {
	roles, err := s.a.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListRolesResponse{}
	for _, r := range roles {
		out.Roles = append(out.Roles, roleProto(r))
	}
	return out, nil
}

// errPrincipalFilter rejects a half-specified principal filter.
var errPrincipalFilter = pcerr.New(pcerr.InvalidArgument, "INVALID_PRINCIPAL", "principal_type and principal_id must be set together")

// ListRoleBindings implements AccessServiceHandler.
func (s *Access) ListRoleBindings(ctx context.Context, req *pantherclawv1.ListRoleBindingsRequest) (*pantherclawv1.ListRoleBindingsResponse, error) {
	pr, err := pageOf(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var filter *td.PrincipalRef
	kind, hasKind := principalTypeFromProto[req.GetPrincipalType()]
	switch {
	case hasKind != (req.GetPrincipalId() != ""):
		return nil, errPrincipalFilter
	case hasKind:
		u, err := ids.ParseUUID(req.GetPrincipalId())
		if err != nil {
			return nil, errInvalidID
		}
		filter = &td.PrincipalRef{Kind: kind, ID: u}
	}
	p, err := s.a.ListRoleBindings(ctx, pr, filter)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListRoleBindingsResponse{NextPageToken: p.Next}
	for _, b := range p.Items {
		out.Bindings = append(out.Bindings, bindingProto(b))
	}
	return out, nil
}

// CreateRoleBinding implements AccessServiceHandler.
func (s *Access) CreateRoleBinding(ctx context.Context, req *pantherclawv1.CreateRoleBindingRequest) (*pantherclawv1.CreateRoleBindingResponse, error) {
	kind := principalTypeFromProto[req.GetPrincipalType()]
	pid, err := parseID[anyID](req.GetPrincipalId())
	if err != nil {
		return nil, err
	}
	scope := td.Scope{Type: scopeTypeFromProto[req.GetScope().GetType()]}
	switch {
	case scope.Type == td.ScopeOrg && req.GetScope().GetId() != "":
		return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_SCOPE", "the org scope takes no id")
	case scope.Type != td.ScopeOrg:
		sid, err := parseID[anyID](req.GetScope().GetId())
		if err != nil {
			return nil, err
		}
		scope.ID = sid.UUID()
	default:
		c, err := app.CallerFrom(ctx)
		if err != nil {
			return nil, err
		}
		scope.ID = c.Org.UUID()
	}
	b, self, err := s.a.CreateRoleBinding(ctx, td.RoleName(req.GetRole()), td.PrincipalRef{Kind: kind, ID: pid.UUID()}, scope)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateRoleBindingResponse{Binding: bindingProto(b), SelfGrant: self}, nil
}

// DeleteRoleBinding implements AccessServiceHandler.
func (s *Access) DeleteRoleBinding(ctx context.Context, req *pantherclawv1.DeleteRoleBindingRequest) (*pantherclawv1.DeleteRoleBindingResponse, error) {
	id, err := parseID[td.RoleBinding](req.GetId())
	if err != nil {
		return nil, err
	}
	if err := s.a.DeleteRoleBinding(ctx, id); err != nil {
		return nil, err
	}
	return &pantherclawv1.DeleteRoleBindingResponse{}, nil
}

// anyID parses ids whose kind depends on another field.
type anyID struct{}

func (anyID) KindName() string { return "id" }
