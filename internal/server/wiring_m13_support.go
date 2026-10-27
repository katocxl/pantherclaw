// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/support"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// The M13 support stream's wiring (G0 M13 D32, D33, D38): customer-approved
// support access and break-glass.

// supportService is the process's support access service.
type supportService = *support.Service

func supportPeriodicJobs() []*river.PeriodicJob { return support.PeriodicJobs() }

// newSupport builds the support access service; it is off unless
// support.staff_org and support.staff_accounts are set.
func newSupport(cfg *Config, pool *db.Pool, ents *entitlements.Service, notify *napp.Service, log *slog.Logger) *support.Service {
	var n support.Notifier
	if notify != nil {
		n = notify
	}
	var plans support.Plans
	if ents != nil {
		plans = ents
	}
	return support.New(pool, cfg.support(), plans, n, log)
}

// supportReadOnly are the procedures a support session may call beyond
// the plan gate's reads (HR-387): who it is and what plan the org has.
var supportReadOnly = map[string]bool{
	pantherclawv1connect.AccessServiceWhoAmIProcedure:                          true,
	pantherclawv1connect.EntitlementServiceGetEntitlementsProcedure:            true,
	pantherclawv1connect.OnboardingServiceGetProgressProcedure:                 true,
	pantherclawv1connect.SupportAccessServiceGetCurrentSupportSessionProcedure: true,
}

// supportMayCall reports whether a support session may call procedure:
// only reads, never a change or a safety action (HR-387).
func supportMayCall(procedure string) bool {
	return supportReadOnly[procedure] || procedureClass(procedure) == entitlements.ClassRead
}

// supportSessions accepts support sessions on the API when support access
// is on.
func supportSessions(s *support.Service) rpcauth.Option {
	return rpcauth.WithSupportAndBreakGlass(s, supportMayCall)
}

// mountSupport adds the support access pages.
func mountSupport(mux *http.ServeMux, d apiDeps) {
	if d.web == nil || d.support == nil {
		return
	}
	d.web.MountBreakGlass(mux, d.support)
	if d.support.Enabled() {
		d.web.MountSupportAccess(mux, d.support)
	}
}

// registerSupport serves SupportAccessService and BreakGlassService.
func registerSupport(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterSupportAccessServiceHandler(rs, supportAccessHandler{s: d.support})
	pantherclawv1connect.RegisterBreakGlassServiceHandler(rs, breakGlassHandler{s: d.support})
}

// supportAccessHandler serves SupportAccessService.
type supportAccessHandler struct {
	pantherclawv1connect.UnimplementedSupportAccessServiceHandler
	s *support.Service
}

func (h supportAccessHandler) on() error {
	if !h.s.Enabled() {
		return support.ErrOff
	}
	return nil
}

// staffOnly answers STEP_UP_REQUIRED to support staff, whose actions
// happen on the pages, and PERMISSION_DENIED to anyone else.
func (h supportAccessHandler) staffOnly(ctx context.Context) error {
	if err := h.on(); err != nil {
		return err
	}
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	ok, err := h.s.IsStaff(ctx, c)
	if err != nil {
		return err
	}
	if !ok {
		return support.ErrNotStaff
	}
	return stepup.ErrStepUp
}

// RequestSupportAccess implements SupportAccessServiceHandler: the page only.
func (h supportAccessHandler) RequestSupportAccess(ctx context.Context, _ *pantherclawv1.RequestSupportAccessRequest) (*pantherclawv1.RequestSupportAccessResponse, error) {
	return nil, h.staffOnly(ctx)
}

// OpenSupportSession implements SupportAccessServiceHandler: the page only.
func (h supportAccessHandler) OpenSupportSession(ctx context.Context, _ *pantherclawv1.OpenSupportSessionRequest) (*pantherclawv1.OpenSupportSessionResponse, error) {
	return nil, h.staffOnly(ctx)
}

// GetCurrentSupportSession implements SupportAccessServiceHandler.
func (h supportAccessHandler) GetCurrentSupportSession(ctx context.Context, _ *pantherclawv1.GetCurrentSupportSessionRequest) (*pantherclawv1.GetCurrentSupportSessionResponse, error) {
	if !h.s.Enabled() {
		return nil, support.ErrNotSupportSession
	}
	id, g, until, err := h.s.Current(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetCurrentSupportSessionResponse{SessionId: id.String(), Grant: grantProto(g), ExpiresAt: timestamppb.New(until)}, nil
}

var supportStates = map[string]pantherclawv1.SupportRequestState{
	support.StatePending:  pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_PENDING,
	support.StateApproved: pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_APPROVED,
	support.StateDenied:   pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_DENIED,
	support.StateExpired:  pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_EXPIRED,
}

var grantStates = map[string]pantherclawv1.SupportGrantState{
	support.GrantActive:  pantherclawv1.SupportGrantState_SUPPORT_GRANT_STATE_ACTIVE,
	support.GrantExpired: pantherclawv1.SupportGrantState_SUPPORT_GRANT_STATE_EXPIRED,
	support.GrantRevoked: pantherclawv1.SupportGrantState_SUPPORT_GRANT_STATE_REVOKED,
}

func scopeProto(s string) pantherclawv1.SupportScope {
	if s == tapp.SupportScopeReadPlusEvidence {
		return pantherclawv1.SupportScope_SUPPORT_SCOPE_READ_ONLY_PLUS_EVIDENCE
	}
	return pantherclawv1.SupportScope_SUPPORT_SCOPE_READ_ONLY
}

func requestProto(r support.Request) *pantherclawv1.SupportRequest {
	out := &pantherclawv1.SupportRequest{
		Id: r.ID.String(), Requester: &pantherclawv1.SupportStaff{AccountId: r.Account.String(), Email: r.Email, DisplayName: r.Name},
		Task: r.Task, Scope: scopeProto(r.Scope), DurationHours: int32(r.Hours), State: supportStates[r.State], //nolint:gosec // G115: 1..72
		CreatedAt: timestamppb.New(r.CreatedAt), ExpiresAt: timestamppb.New(r.ExpiresAt),
		ConfirmUrl: "/support-access/" + r.ID.String(),
	}
	if r.DecidedBy != nil {
		out.DecidedBy = r.DecidedBy.String()
	}
	if r.DecidedAt != nil {
		out.DecidedAt = timestamppb.New(*r.DecidedAt)
	}
	if r.Grant != nil {
		out.GrantId = r.Grant.String()
	}
	return out
}

func grantProto(g support.Grant) *pantherclawv1.SupportGrant {
	out := &pantherclawv1.SupportGrant{
		Id: g.ID.String(), RequestId: g.Request.String(),
		Staff: &pantherclawv1.SupportStaff{AccountId: g.Account.String(), Email: g.Email, DisplayName: g.Name},
		Task:  g.Task, Scope: scopeProto(g.Scope), State: grantStates[g.State], ApprovedBy: g.ApprovedBy.String(),
		StartsAt: timestamppb.New(g.StartsAt), ExpiresAt: timestamppb.New(g.ExpiresAt), RevokedBy: g.RevokedBy,
		SessionsOpened: int32(g.Sessions), //nolint:gosec // G115: a count of sessions
	}
	if g.RevokedAt != nil {
		out.RevokedAt = timestamppb.New(*g.RevokedAt)
	}
	return out
}

var supportStateNames = map[pantherclawv1.SupportRequestState]string{
	pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_PENDING:  support.StatePending,
	pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_APPROVED: support.StateApproved,
	pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_DENIED:   support.StateDenied,
	pantherclawv1.SupportRequestState_SUPPORT_REQUEST_STATE_EXPIRED:  support.StateExpired,
}

// ListSupportRequests implements SupportAccessServiceHandler.
func (h supportAccessHandler) ListSupportRequests(ctx context.Context, req *pantherclawv1.ListSupportRequestsRequest) (*pantherclawv1.ListSupportRequestsResponse, error) {
	if err := h.on(); err != nil {
		return nil, err
	}
	p, err := h.s.ListRequests(ctx, supportStateNames[req.GetState()], req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSupportRequestsResponse{NextPageToken: p.Next}
	for _, r := range p.Items {
		out.Requests = append(out.Requests, requestProto(r))
	}
	return out, nil
}

// GetSupportRequest implements SupportAccessServiceHandler.
func (h supportAccessHandler) GetSupportRequest(ctx context.Context, req *pantherclawv1.GetSupportRequestRequest) (*pantherclawv1.GetSupportRequestResponse, error) {
	if err := h.on(); err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, support.ErrRequestNotFound
	}
	r, g, err := h.s.GetRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetSupportRequestResponse{Request: requestProto(r)}
	if g != nil {
		out.Grant = grantProto(*g)
	}
	return out, nil
}

// ApproveSupportRequest implements SupportAccessServiceHandler: it needs a
// step-up, which only the request's page has (HR-386).
func (h supportAccessHandler) ApproveSupportRequest(ctx context.Context, req *pantherclawv1.ApproveSupportRequestRequest) (*pantherclawv1.ApproveSupportRequestResponse, error) {
	if err := h.on(); err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, support.ErrRequestNotFound
	}
	_, g, err := h.s.Decide(ctx, id, true, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ApproveSupportRequestResponse{Grant: grantProto(*g)}, nil
}

// DenySupportRequest implements SupportAccessServiceHandler: like
// approving, the page only.
func (h supportAccessHandler) DenySupportRequest(ctx context.Context, req *pantherclawv1.DenySupportRequestRequest) (*pantherclawv1.DenySupportRequestResponse, error) {
	if err := h.on(); err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, support.ErrRequestNotFound
	}
	if _, _, err := h.s.Decide(ctx, id, false, nil); err != nil {
		return nil, err
	}
	return &pantherclawv1.DenySupportRequestResponse{}, nil
}

// ListSupportGrants implements SupportAccessServiceHandler.
func (h supportAccessHandler) ListSupportGrants(ctx context.Context, req *pantherclawv1.ListSupportGrantsRequest) (*pantherclawv1.ListSupportGrantsResponse, error) {
	if err := h.on(); err != nil {
		return nil, err
	}
	p, err := h.s.ListGrants(ctx, req.GetActiveOnly(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSupportGrantsResponse{NextPageToken: p.Next}
	for _, g := range p.Items {
		out.Grants = append(out.Grants, grantProto(g))
	}
	return out, nil
}

// RevokeSupportGrant implements SupportAccessServiceHandler.
func (h supportAccessHandler) RevokeSupportGrant(ctx context.Context, req *pantherclawv1.RevokeSupportGrantRequest) (*pantherclawv1.RevokeSupportGrantResponse, error) {
	if err := h.on(); err != nil {
		return nil, err
	}
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, support.ErrGrantNotFound
	}
	g, err := h.s.Revoke(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeSupportGrantResponse{Grant: grantProto(g)}, nil
}
