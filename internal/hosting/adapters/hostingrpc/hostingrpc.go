// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package hostingrpc serves HostedGatewayService (an org's people) and
// HostingAgentService (host agents, on the gateway listener) for
// PantherClaw-hosted gateways (G0 M19 D203).
//
// A host agent is authenticated by its host certificate alone: HostIdentity
// reads the purpose "hosting" form, which never parses as a gateway, and
// HostAuthenticator admits only HostingAgentService's procedures. The
// gateway listener's own authenticator never admits a host certificate, so
// a host can never call an org RPC (HR-500).
package hostingrpc

import (
	"context"
	"net/http"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/app"
	"github.com/katocxl/pantherclaw/internal/hosting/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

type hostKey struct{}

// HostIdentity puts the host identity of a verified client certificate
// into the request context. A certificate of any other form (a gateway's)
// leaves the context empty, and HostAuthenticator refuses it.
func HostIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			if id, err := ca.ParseHostIdentity(r.TLS.VerifiedChains[0][0]); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), hostKey{}, id))
			}
		}
		next.ServeHTTP(w, r)
	})
}

// HostFrom returns the authenticated host identity.
func HostFrom(ctx context.Context) (app.HostIdentity, bool) {
	id, ok := ctx.Value(hostKey{}).(app.HostIdentity)
	return id, ok
}

// AgentProcedures are HostingAgentService's procedures: the only ones a
// host certificate reaches.
var AgentProcedures = map[string]td.Permission{
	pantherclawv1connect.HostingAgentServiceListAssignmentsProcedure:      PermHostingAgent,
	pantherclawv1connect.HostingAgentServicePullEnrollmentTokenProcedure:  PermHostingAgent,
	pantherclawv1connect.HostingAgentServiceReportHostedGatewayProcedure:  PermHostingAgent,
	pantherclawv1connect.HostingAgentServiceReportStoppedProcedure:        PermHostingAgent,
	pantherclawv1connect.HostingAgentServiceRenewHostCertificateProcedure: PermHostingAgent,
}

// PermHostingAgent is the requirement of HostingAgentService's procedures:
// a host certificate's row checked on every call, never a role.
const PermHostingAgent = td.PermHostingAgent

// HostAuthenticator admits a call only to a HostingAgentService procedure
// and only with a host certificate whose row passes AuthenticateHost.
func HostAuthenticator(s *app.Service) rpc.Authenticator {
	return func(ctx context.Context, _ *connect.CallInfo, spec connect.Spec) (context.Context, error) {
		if _, ok := AgentProcedures[spec.Procedure]; !ok {
			return nil, connect.NewError(connect.CodePermissionDenied, "permission denied")
		}
		id, ok := HostFrom(ctx)
		if !ok {
			return nil, connect.NewError(connect.CodeUnauthenticated, "hosting host credentials required")
		}
		if err := s.AuthenticateHost(ctx, id); err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, "hosting host credentials required")
		}
		return ctx, nil
	}
}

var states = map[string]pantherclawv1.HostedGatewayState{
	domain.StateRequested:      pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_REQUESTED,
	domain.StateProvisioned:    pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_PROVISIONED,
	domain.StateEnrolled:       pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_ENROLLED,
	domain.StateRunning:        pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_RUNNING,
	domain.StateDeprovisioning: pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_DEPROVISIONING,
	domain.StateDeprovisioned:  pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_DEPROVISIONED,
	domain.StateFailed:         pantherclawv1.HostedGatewayState_HOSTED_GATEWAY_STATE_FAILED,
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func id(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func limitsOf(l profile.Limits) *pantherclawv1.HostedGatewayLimits {
	return &pantherclawv1.HostedGatewayLimits{MilliCpus: int32(l.MilliCPUs), MemoryMib: int32(l.MemoryMiB), Pids: int32(l.PIDs)} //nolint:gosec // G115: bounded by the profile's ceilings
}

func hostedOf(h dbq.PcHostedGateway) *pantherclawv1.HostedGateway {
	return &pantherclawv1.HostedGateway{
		Id: h.ID.String(), Slug: h.Slug, State: states[h.State], GatewayId: id(h.GatewayID),
		Limits:  &pantherclawv1.HostedGatewayLimits{MilliCpus: h.MilliCpus, MemoryMib: h.MemoryMib, Pids: h.Pids},
		Version: str(h.Version), TargetVersion: str(h.TargetVersion), CreatedBy: h.CreatedBy,
		CreateTime: timestamppb.New(h.CreatedAt), UpdateTime: timestamppb.New(h.UpdatedAt),
	}
}

// Handler serves HostedGatewayService.
type Handler struct {
	pantherclawv1connect.UnimplementedHostedGatewayServiceHandler
	s *app.Service
}

// New returns the HostedGatewayService handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

var _ pantherclawv1connect.HostedGatewayServiceHandler = (*Handler)(nil)

// RequestHostedGateway asks for the org's hosted gateway.
func (h *Handler) RequestHostedGateway(ctx context.Context, req *pantherclawv1.RequestHostedGatewayRequest) (*pantherclawv1.RequestHostedGatewayResponse, error) {
	var l profile.Limits
	if x := req.GetLimits(); x != nil {
		l = profile.Limits{MilliCPUs: int(x.GetMilliCpus()), MemoryMiB: int(x.GetMemoryMib()), PIDs: int(x.GetPids())}
	}
	r, err := h.s.Request(ctx, req.GetSlug(), l)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestHostedGatewayResponse{HostedGateway: hostedOf(r)}, nil
}

// GetHostedGateway returns one record.
func (h *Handler) GetHostedGateway(ctx context.Context, req *pantherclawv1.GetHostedGatewayRequest) (*pantherclawv1.GetHostedGatewayResponse, error) {
	hid, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	r, err := h.s.Get(ctx, hid)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetHostedGatewayResponse{HostedGateway: hostedOf(r)}, nil
}

// ListHostedGateways lists the org's records.
func (h *Handler) ListHostedGateways(ctx context.Context, req *pantherclawv1.ListHostedGatewaysRequest) (*pantherclawv1.ListHostedGatewaysResponse, error) {
	rows, next, err := h.s.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListHostedGatewaysResponse{NextPageToken: next}
	for _, r := range rows {
		out.HostedGateways = append(out.HostedGateways, hostedOf(r))
	}
	return out, nil
}

// DeprovisionHostedGateway revokes first, then stops (HR-503).
func (h *Handler) DeprovisionHostedGateway(ctx context.Context, req *pantherclawv1.DeprovisionHostedGatewayRequest) (*pantherclawv1.DeprovisionHostedGatewayResponse, error) {
	hid, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	r, err := h.s.Deprovision(ctx, hid, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DeprovisionHostedGatewayResponse{HostedGateway: hostedOf(r)}, nil
}

// AgentHandler serves HostingAgentService.
type AgentHandler struct {
	pantherclawv1connect.UnimplementedHostingAgentServiceHandler
	s *app.Service
}

// NewAgent returns the HostingAgentService handler.
func NewAgent(s *app.Service) *AgentHandler { return &AgentHandler{s: s} }

var _ pantherclawv1connect.HostingAgentServiceHandler = (*AgentHandler)(nil)

func host(ctx context.Context) (app.HostIdentity, error) {
	id, ok := HostFrom(ctx)
	if !ok {
		return app.HostIdentity{}, app.ErrHostCredentials
	}
	return id, nil
}

func target(org, hosted string) (ids.OrgID, ids.UUID, error) {
	o, err1 := ids.Parse[ids.Org](org)
	h, err2 := ids.ParseUUID(hosted)
	if err1 != nil || err2 != nil {
		return ids.OrgID{}, ids.UUID{}, errInvalidID
	}
	return o, h, nil
}

// ListAssignments lists the calling host's hosted gateways.
func (a *AgentHandler) ListAssignments(ctx context.Context, req *pantherclawv1.ListAssignmentsRequest) (*pantherclawv1.ListAssignmentsResponse, error) {
	hid, err := host(ctx)
	if err != nil {
		return nil, err
	}
	as, err := a.s.Assignments(ctx, hid, req.GetAgentVersion())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAssignmentsResponse{}
	for _, x := range as {
		out.Assignments = append(out.Assignments, &pantherclawv1.HostingAssignment{
			OrgId: x.Org.String(), Id: x.ID.String(), Slug: x.Slug, Hostname: x.Hostname, State: states[x.State],
			GatewayId: x.Gateway.String(), Limits: limitsOf(x.Limits), Version: x.Version, TargetVersion: x.TargetVersion,
		})
	}
	return out, nil
}

// PullEnrollmentToken returns a token once (HR-502).
func (a *AgentHandler) PullEnrollmentToken(ctx context.Context, req *pantherclawv1.PullEnrollmentTokenRequest) (*pantherclawv1.PullEnrollmentTokenResponse, error) {
	hid, err := host(ctx)
	if err != nil {
		return nil, err
	}
	org, hosted, err := target(req.GetOrgId(), req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := a.s.PullToken(ctx, hid, org, hosted)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PullEnrollmentTokenResponse{Token: t.Secret.Reveal(), GatewayApiUrl: t.GatewayAPIURL, CaSha256: t.CAFingerprint}, nil
}

// ReportHostedGateway records a process's health and version.
func (a *AgentHandler) ReportHostedGateway(ctx context.Context, req *pantherclawv1.ReportHostedGatewayRequest) (*pantherclawv1.ReportHostedGatewayResponse, error) {
	hid, err := host(ctx)
	if err != nil {
		return nil, err
	}
	org, hosted, err := target(req.GetOrgId(), req.GetId())
	if err != nil {
		return nil, err
	}
	if err := a.s.Report(ctx, hid, org, hosted, req.GetHealthy(), req.GetVersion()); err != nil {
		return nil, err
	}
	return &pantherclawv1.ReportHostedGatewayResponse{}, nil
}

// ReportStopped records a stopped process.
func (a *AgentHandler) ReportStopped(ctx context.Context, req *pantherclawv1.ReportStoppedRequest) (*pantherclawv1.ReportStoppedResponse, error) {
	hid, err := host(ctx)
	if err != nil {
		return nil, err
	}
	org, hosted, err := target(req.GetOrgId(), req.GetId())
	if err != nil {
		return nil, err
	}
	if err := a.s.Stopped(ctx, hid, org, hosted); err != nil {
		return nil, err
	}
	return &pantherclawv1.ReportStoppedResponse{}, nil
}

// RenewHostCertificate issues a certificate for a new key.
func (a *AgentHandler) RenewHostCertificate(ctx context.Context, req *pantherclawv1.RenewHostCertificateRequest) (*pantherclawv1.RenewHostCertificateResponse, error) {
	hid, err := host(ctx)
	if err != nil {
		return nil, err
	}
	pub, err := ca.ParseRequest(req.GetCsr())
	if err != nil {
		return nil, pcerr.New(pcerr.InvalidArgument, "CSR_INVALID", "invalid certificate request")
	}
	c, err := a.s.RenewHost(ctx, hid, pub)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RenewHostCertificateResponse{Certificate: c.Certificate, CaCertificate: c.CACertificate}, nil
}
