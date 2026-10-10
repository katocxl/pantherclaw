// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gatewaysrpc serves GatewayAdminService (people) and
// GatewayService (gateways), and authenticates gateways by their client
// certificate on the server's gateway listener (G0 M6, HR-180, HR-181).
package gatewaysrpc

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authority"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

type identityKey struct{}

// TLSIdentity puts the gateway identity of a verified client certificate
// into the request context. It sits in front of the gateway listener's RPC
// server, whose TLS configuration has already verified the chain to the
// internal CA (RequireAndVerifyClientCert); a certificate that names no
// gateway leaves the context empty, and the authenticator refuses it.
func TLSIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			if id, err := ca.ParseIdentity(r.TLS.VerifiedChains[0][0]); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// IdentityFrom returns the authenticated gateway identity.
func IdentityFrom(ctx context.Context) (gwapp.Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(gwapp.Identity)
	return id, ok
}

// Authenticator authenticates every procedure on the gateway listener: the
// procedure must declare a gateway permission, and the certificate's row
// must pass gwapp.Service.Authenticate (HR-181). The org then comes only
// from the certificate; the Authority sees the gateway as
// authority.Gateway{ID: <gateway id>, Org: <org>} (HR-020).
func Authenticator(s *gwapp.Service, perms map[string]td.Permission) rpc.Authenticator {
	return func(ctx context.Context, _ *connect.CallInfo, spec connect.Spec) (context.Context, error) {
		if p, ok := perms[spec.Procedure]; !ok || !p.Gateway() {
			return nil, connect.NewError(connect.CodePermissionDenied, "permission denied")
		}
		id, ok := IdentityFrom(ctx)
		if !ok {
			return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
		}
		if err := s.Authenticate(ctx, id); err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
		}
		return authority.WithGateway(ctx, authority.Gateway{ID: id.Gateway.String(), Org: id.Org}), nil
	}
}

// AdminHandler serves GatewayAdminService.
type AdminHandler struct {
	pantherclawv1connect.UnimplementedGatewayAdminServiceHandler
	s *gwapp.Service
}

// NewAdmin returns the GatewayAdminService handler.
func NewAdmin(s *gwapp.Service) *AdminHandler { return &AdminHandler{s: s} }

var _ pantherclawv1connect.GatewayAdminServiceHandler = (*AdminHandler)(nil)

func gatewayOf(g dbq.PcGateway) *pantherclawv1.Gateway {
	out := &pantherclawv1.Gateway{
		Id: g.ID.String(), Name: g.Name, ConfigVersion: g.ConfigVersion, CreatedBy: g.CreatedBy, CreateTime: timestamppb.New(g.CreatedAt),
		State: pantherclawv1.GatewayState_GATEWAY_STATE_ACTIVE,
	}
	if g.State == "REVOKED" {
		out.State = pantherclawv1.GatewayState_GATEWAY_STATE_REVOKED
	}
	if g.RevokedBy != nil {
		out.RevokedBy = *g.RevokedBy
	}
	if g.RevokedAt != nil {
		out.RevokeTime = timestamppb.New(*g.RevokedAt)
	}
	if g.RevokeReason != nil {
		out.RevokeReason = *g.RevokeReason
	}
	return out
}

var certStates = map[string]pantherclawv1.GatewayCertificateState{
	"ACTIVE":     pantherclawv1.GatewayCertificateState_GATEWAY_CERTIFICATE_STATE_ACTIVE,
	"SUPERSEDED": pantherclawv1.GatewayCertificateState_GATEWAY_CERTIFICATE_STATE_SUPERSEDED,
	"REVOKED":    pantherclawv1.GatewayCertificateState_GATEWAY_CERTIFICATE_STATE_REVOKED,
}

func certOf(c dbq.PcGatewayCert) *pantherclawv1.GatewayCertificate {
	out := &pantherclawv1.GatewayCertificate{
		Id: c.ID.String(), Serial: hex.EncodeToString(c.Serial), KeyThumbprint: c.KeyThumbprint, State: certStates[c.State],
		IssuedVia: c.IssuedVia, NotBefore: timestamppb.New(c.NotBefore), NotAfter: timestamppb.New(c.NotAfter),
	}
	if c.RevokeReason != nil {
		out.RevokeReason = *c.RevokeReason
	}
	return out
}

// BrokerKeyOf maps a broker key row.
func BrokerKeyOf(k dbq.PcBrokerKey) *pantherclawv1.BrokerKey {
	return &pantherclawv1.BrokerKey{
		Id: k.ID.String(), Version: k.Version, Fingerprint: k.Fingerprint, Active: k.State == "ACTIVE",
		RegisterTime: timestamppb.New(k.RegisteredAt), CertificateId: k.CertID.String(),
	}
}

// CreateGateway implements GatewayAdminServiceHandler.
func (h *AdminHandler) CreateGateway(ctx context.Context, req *pantherclawv1.CreateGatewayRequest) (*pantherclawv1.CreateGatewayResponse, error) {
	g, err := h.s.CreateGateway(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateGatewayResponse{Gateway: gatewayOf(g)}, nil
}

// CreateGatewayEnrollmentToken implements GatewayAdminServiceHandler.
func (h *AdminHandler) CreateGatewayEnrollmentToken(ctx context.Context, req *pantherclawv1.CreateGatewayEnrollmentTokenRequest) (*pantherclawv1.CreateGatewayEnrollmentTokenResponse, error) {
	id, err := ids.ParseUUID(req.GetGatewayId())
	if err != nil {
		return nil, errInvalidID
	}
	tok, err := h.s.CreateEnrollmentToken(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateGatewayEnrollmentTokenResponse{
		Token: tok.Secret.Reveal(), ExpireTime: timestamppb.New(tok.ExpiresAt), CaSha256: tok.CAFingerprint, GatewayApiUrl: tok.GatewayAPIURL,
	}, nil
}

// ListGateways implements GatewayAdminServiceHandler.
func (h *AdminHandler) ListGateways(ctx context.Context, req *pantherclawv1.ListGatewaysRequest) (*pantherclawv1.ListGatewaysResponse, error) {
	rows, next, err := h.s.ListGateways(ctx, req.GetPageSize(), req.GetPageToken(), req.GetIncludeRevoked())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListGatewaysResponse{NextPageToken: next}
	for _, g := range rows {
		out.Gateways = append(out.Gateways, gatewayOf(g))
	}
	return out, nil
}

// GetGateway implements GatewayAdminServiceHandler.
func (h *AdminHandler) GetGateway(ctx context.Context, req *pantherclawv1.GetGatewayRequest) (*pantherclawv1.GetGatewayResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	d, err := h.s.GetGateway(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetGatewayResponse{Gateway: gatewayOf(d.Gateway)}
	for _, c := range d.Certificates {
		out.Certificates = append(out.Certificates, certOf(c))
	}
	for _, k := range d.BrokerKeys {
		out.BrokerKeys = append(out.BrokerKeys, BrokerKeyOf(k))
	}
	return out, nil
}

// RevokeGateway implements GatewayAdminServiceHandler.
func (h *AdminHandler) RevokeGateway(ctx context.Context, req *pantherclawv1.RevokeGatewayRequest) (*pantherclawv1.RevokeGatewayResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	g, err := h.s.RevokeGateway(ctx, id, strings.ToValidUTF8(req.GetReason(), ""))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeGatewayResponse{Gateway: gatewayOf(g)}, nil
}

// RevokeGatewayCertificate implements GatewayAdminServiceHandler.
func (h *AdminHandler) RevokeGatewayCertificate(ctx context.Context, req *pantherclawv1.RevokeGatewayCertificateRequest) (*pantherclawv1.RevokeGatewayCertificateResponse, error) {
	gw, err1 := ids.ParseUUID(req.GetGatewayId())
	cert, err2 := ids.ParseUUID(req.GetCertificateId())
	if err1 != nil || err2 != nil {
		return nil, errInvalidID
	}
	if err := h.s.RevokeCertificate(ctx, gw, cert); err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeGatewayCertificateResponse{}, nil
}

// GatewayHandler serves GatewayService. Configuration, the containment
// stream and the reports are served by the handlers that WithSync adds
// (later M6 slices); until then they are unimplemented.
type GatewayHandler struct {
	pantherclawv1connect.UnimplementedGatewayServiceHandler
	s        *gwapp.Service
	hub      *gwapp.Hub
	circuits Circuits
	drifts   Drifts
	// verifications leases and takes verification reports (G0 M7).
	verifications Verifications
}

// NewGateway returns the GatewayService handler.
func NewGateway(s *gwapp.Service) *GatewayHandler { return &GatewayHandler{s: s} }

var _ pantherclawv1connect.GatewayServiceHandler = (*GatewayHandler)(nil)

func identity(ctx context.Context) (gwapp.Identity, error) {
	id, ok := IdentityFrom(ctx)
	if !ok {
		return gwapp.Identity{}, connect.NewError(connect.CodeUnauthenticated, "gateway credentials required")
	}
	return id, nil
}

// Enroll implements GatewayServiceHandler. It runs on the public API with
// no principal: the enrollment token authenticates it (HR-180).
func (h *GatewayHandler) Enroll(ctx context.Context, req *pantherclawv1.GatewayServiceEnrollRequest) (*pantherclawv1.GatewayServiceEnrollResponse, error) {
	en, err := h.s.Enroll(ctx, req.GetToken(), req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GatewayServiceEnrollResponse{
		Certificate: en.Certificate, CaCertificate: en.CACertificate, GatewayId: en.Gateway.String(), OrgId: en.Org.String(),
		GatewayApiUrl: en.GatewayAPIURL,
	}, nil
}

// RenewCertificate implements GatewayServiceHandler.
func (h *GatewayHandler) RenewCertificate(ctx context.Context, req *pantherclawv1.RenewCertificateRequest) (*pantherclawv1.RenewCertificateResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	en, err := h.s.Renew(ctx, id, req.GetCsr())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RenewCertificateResponse{Certificate: en.Certificate, CaCertificate: en.CACertificate}, nil
}

// RegisterBrokerKey implements GatewayServiceHandler.
func (h *GatewayHandler) RegisterBrokerKey(ctx context.Context, req *pantherclawv1.RegisterBrokerKeyRequest) (*pantherclawv1.RegisterBrokerKeyResponse, error) {
	id, err := identity(ctx)
	if err != nil {
		return nil, err
	}
	k, err := h.s.RegisterBrokerKey(ctx, id, req.GetPublicKey())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RegisterBrokerKeyResponse{BrokerKey: BrokerKeyOf(k)}, nil
}
