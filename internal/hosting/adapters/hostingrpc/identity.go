// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package hostingrpc

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gateways/adapters/gatewaysrpc"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// IdentityHandler serves HostedGatewayIdentityService on the gateway
// listener, behind the gateway authenticator: the caller is a gateway, by
// its own certificate (G0 M19 D210).
type IdentityHandler struct {
	pantherclawv1connect.UnimplementedHostedGatewayIdentityServiceHandler
	s *app.Service
}

// NewIdentity returns the HostedGatewayIdentityService handler.
func NewIdentity(s *app.Service) *IdentityHandler { return &IdentityHandler{s: s} }

var _ pantherclawv1connect.HostedGatewayIdentityServiceHandler = (*IdentityHandler)(nil)

// IssueServerCertificate issues the calling hosted gateway its
// agent-facing certificate; the name comes from its record.
func (h *IdentityHandler) IssueServerCertificate(ctx context.Context, req *pantherclawv1.IssueServerCertificateRequest) (*pantherclawv1.IssueServerCertificateResponse, error) {
	id, ok := gatewaysrpc.IdentityFrom(ctx)
	if !ok {
		return nil, app.ErrNotHosted
	}
	pub, err := ca.ParseRequest(req.GetCsr())
	if err != nil {
		return nil, pcerr.New(pcerr.InvalidArgument, "CSR_INVALID", "invalid certificate request")
	}
	c, err := h.s.IssueServerCertificate(ctx, id, pub)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.IssueServerCertificateResponse{Certificate: c.Certificate, CaCertificate: c.CACertificate, Hostname: c.Hostname}, nil
}
