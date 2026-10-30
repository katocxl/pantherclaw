// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package idpsrpc serves IdentityProviderService over Connect (G0 M18
// D155). Every write files a protected change and returns it; nothing
// here applies one. Client secrets come in and never go out (HR-482).
package idpsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/idps"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Handler serves IdentityProviderService.
type Handler struct {
	pantherclawv1connect.UnimplementedIdentityProviderServiceHandler
	s *idps.Service
}

// New returns the handler.
func New(s *idps.Service) *Handler { return &Handler{s: s} }

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

// Proto is a provider as the API shows it: never its secret.
func Proto(p idps.Provider) *pantherclawv1.IdentityProvider {
	return &pantherclawv1.IdentityProvider{
		Id: p.ID.String(), Name: p.Name, Issuer: p.Issuer, ClientId: p.ClientID, TrustEmail: p.TrustEmail, State: p.State,
		CreatedBy: p.CreatedBy.String(), CreateTime: timestamppb.New(p.CreatedAt), UpdatedBy: p.UpdatedBy.String(),
		UpdateTime: timestamppb.New(p.UpdatedAt), ActivateTime: tsp(p.ActivatedAt), DisableTime: tsp(p.DisabledAt),
	}
}

func filed(f idps.Filed) *pantherclawv1.ProtectedChangeFiled {
	out := &pantherclawv1.ProtectedChangeFiled{ProtectedChangeId: f.Change.String(), ChangeRequestId: f.Request.String()}
	for _, u := range f.Stranded {
		out.StrandedAdminIds = append(out.StrandedAdminIds, u.String())
	}
	return out
}

func secret(b []byte) pclog.Secret[[]byte] {
	if len(b) == 0 {
		return pclog.Secret[[]byte]{}
	}
	return pclog.NewSecret(b)
}

// CreateIdentityProvider implements IdentityProviderServiceHandler.
func (h *Handler) CreateIdentityProvider(ctx context.Context, req *pantherclawv1.CreateIdentityProviderRequest) (
	*pantherclawv1.CreateIdentityProviderResponse, error,
) {
	p, f, err := h.s.Create(ctx, idps.Input{
		Name: req.GetName(), Issuer: req.GetIssuer(), ClientID: req.GetClientId(), ClientSecret: secret(req.GetClientSecret()),
		TrustEmail: req.GetTrustEmail(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateIdentityProviderResponse{Provider: Proto(p), Change: filed(f)}, nil
}

// UpdateIdentityProvider implements IdentityProviderServiceHandler.
func (h *Handler) UpdateIdentityProvider(ctx context.Context, req *pantherclawv1.UpdateIdentityProviderRequest) (
	*pantherclawv1.UpdateIdentityProviderResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.s.Update(ctx, id, idps.Input{
		Name: req.GetName(), Issuer: req.GetIssuer(), ClientID: req.GetClientId(), ClientSecret: secret(req.GetClientSecret()),
		TrustEmail: req.GetTrustEmail(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateIdentityProviderResponse{Change: filed(f)}, nil
}

// DisableIdentityProvider implements IdentityProviderServiceHandler.
func (h *Handler) DisableIdentityProvider(ctx context.Context, req *pantherclawv1.DisableIdentityProviderRequest) (
	*pantherclawv1.DisableIdentityProviderResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.s.Disable(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableIdentityProviderResponse{Change: filed(f)}, nil
}

// SetOwnProvidersOnly implements IdentityProviderServiceHandler.
func (h *Handler) SetOwnProvidersOnly(ctx context.Context, req *pantherclawv1.SetOwnProvidersOnlyRequest) (
	*pantherclawv1.SetOwnProvidersOnlyResponse, error,
) {
	f, err := h.s.SetOwnOnly(ctx, req.GetOwnProvidersOnly())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetOwnProvidersOnlyResponse{Change: filed(f)}, nil
}

// GetIdentityProvider implements IdentityProviderServiceHandler.
func (h *Handler) GetIdentityProvider(ctx context.Context, req *pantherclawv1.GetIdentityProviderRequest) (
	*pantherclawv1.GetIdentityProviderResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetIdentityProviderResponse{Provider: Proto(p)}, nil
}

// ListIdentityProviders implements IdentityProviderServiceHandler.
func (h *Handler) ListIdentityProviders(ctx context.Context, _ *pantherclawv1.ListIdentityProvidersRequest) (
	*pantherclawv1.ListIdentityProvidersResponse, error,
) {
	ps, only, err := h.s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListIdentityProvidersResponse{OwnProvidersOnly: only}
	for _, p := range ps {
		out.Providers = append(out.Providers, Proto(p))
	}
	return out, nil
}
