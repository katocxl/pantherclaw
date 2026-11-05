// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package partnersrpc serves PartnerService over Connect (G0 M38
// D1100–D1102; HR-810..816).
package partnersrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/partners"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves PartnerService.
type Handler struct {
	pantherclawv1connect.UnimplementedPartnerServiceHandler
	svc *partners.Service
}

// New returns the PartnerService handler.
func New(svc *partners.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optID(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

var scopeProto = map[string]pantherclawv1.PartnerLinkScope{
	partners.ScopeRead:    pantherclawv1.PartnerLinkScope_PARTNER_LINK_SCOPE_READ,
	partners.ScopePropose: pantherclawv1.PartnerLinkScope_PARTNER_LINK_SCOPE_PROPOSE,
}

func scopes(in []string) []pantherclawv1.PartnerLinkScope {
	out := make([]pantherclawv1.PartnerLinkScope, 0, len(in))
	for _, s := range in {
		if p, ok := scopeProto[s]; ok {
			out = append(out, p)
		}
	}
	return out
}

var kindProto = map[string]pantherclawv1.PartnerProposalKind{
	partners.KindPolicyVersion: pantherclawv1.PartnerProposalKind_PARTNER_PROPOSAL_KIND_POLICY_VERSION,
	partners.KindPack:          pantherclawv1.PartnerProposalKind_PARTNER_PROPOSAL_KIND_PACK,
}

var kindName = map[pantherclawv1.PartnerProposalKind]string{
	pantherclawv1.PartnerProposalKind_PARTNER_PROPOSAL_KIND_POLICY_VERSION: partners.KindPolicyVersion,
	pantherclawv1.PartnerProposalKind_PARTNER_PROPOSAL_KIND_PACK:           partners.KindPack,
}

func (h *Handler) link(l partners.Link) *pantherclawv1.PartnerLink {
	out := &pantherclawv1.PartnerLink{
		Id: l.ID.String(), PartnerOrgId: l.PartnerOrg.String(), PartnerName: l.PartnerName,
		CustomerOrgId: l.CustomerOrg.String(), State: l.State, Scopes: scopes(l.Scopes),
		DurationDays: int32(l.DurationDays), Reason: l.Reason, Renews: optID(l.Renews), //nolint:gosec // G115: 1..90
		RequestedBy: l.RequestedBy.String(), RequestTime: timestamppb.New(l.RequestedAt),
		RequestExpireTime: timestamppb.New(l.RequestExpiresAt), DecidedBy: optID(l.DecidedBy), DecideTime: ts(l.DecidedAt),
		StartTime: ts(l.StartsAt), EndTime: ts(l.EndsAt), RevokedBy: l.RevokedBy, RevokeTime: ts(l.RevokedAt),
		EndReason: l.EndReason, DecideUrl: h.svc.DecideURL(l.ID), OpenUrl: h.svc.OpenURL(l.CustomerOrg),
	}
	return out
}

func proposal(p partners.Proposal) *pantherclawv1.PartnerProposal {
	return &pantherclawv1.PartnerProposal{
		Id: p.ID.String(), LinkId: p.Link.String(), PartnerOrgId: p.PartnerOrg.String(), CustomerOrgId: p.CustomerOrg.String(),
		Kind: kindProto[p.Kind], Title: p.Title, Body: p.Body, TemplateId: optID(p.Template), State: p.State,
		ProposedBy: p.ProposedBy, CreateTime: timestamppb.New(p.CreatedAt), ExpireTime: timestamppb.New(p.ExpiresAt),
		DecidedBy: p.DecidedBy, DecideTime: ts(p.DecidedAt), DeclineReason: p.DeclineReason, DraftVersionId: optID(p.Draft),
	}
}

func hasScope(in []pantherclawv1.PartnerLinkScope, s pantherclawv1.PartnerLinkScope) bool {
	for _, x := range in {
		if x == s {
			return true
		}
	}
	return false
}

// RequestPartnerLink implements PartnerServiceHandler.
func (h *Handler) RequestPartnerLink(ctx context.Context, req *pantherclawv1.RequestPartnerLinkRequest) (
	*pantherclawv1.RequestPartnerLinkResponse, error,
) {
	customer, err := idOf(req.GetCustomerOrgId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.Request(ctx, partners.NewLink{
		Customer: customer, Propose: hasScope(req.GetScopes(), pantherclawv1.PartnerLinkScope_PARTNER_LINK_SCOPE_PROPOSE),
		Days: int(req.GetDurationDays()), Reason: req.GetReason(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestPartnerLinkResponse{Link: h.link(l)}, nil
}

// RenewPartnerLink implements PartnerServiceHandler.
func (h *Handler) RenewPartnerLink(ctx context.Context, req *pantherclawv1.RenewPartnerLinkRequest) (
	*pantherclawv1.RenewPartnerLinkResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.Renew(ctx, id, int(req.GetDurationDays()), req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RenewPartnerLinkResponse{Link: h.link(l)}, nil
}

// ListPartnerLinks implements PartnerServiceHandler.
func (h *Handler) ListPartnerLinks(ctx context.Context, req *pantherclawv1.ListPartnerLinksRequest) (
	*pantherclawv1.ListPartnerLinksResponse, error,
) {
	ls, next, err := h.svc.List(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPartnerLinksResponse{NextPageToken: next}
	for _, l := range ls {
		out.Links = append(out.Links, h.link(l))
	}
	return out, nil
}

// GetPartnerLink implements PartnerServiceHandler.
func (h *Handler) GetPartnerLink(ctx context.Context, req *pantherclawv1.GetPartnerLinkRequest) (
	*pantherclawv1.GetPartnerLinkResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPartnerLinkResponse{Link: h.link(l)}, nil
}

// DecidePartnerLink implements PartnerServiceHandler: over the API it is
// always refused (STEP_UP_REQUIRED); a customer person decides on the
// link's page with a security key (HR-810).
func (h *Handler) DecidePartnerLink(ctx context.Context, req *pantherclawv1.DecidePartnerLinkRequest) (
	*pantherclawv1.DecidePartnerLinkResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.Decide(ctx, id, req.GetApprove(), nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DecidePartnerLinkResponse{Link: h.link(l)}, nil
}

// RevokePartnerLink implements PartnerServiceHandler.
func (h *Handler) RevokePartnerLink(ctx context.Context, req *pantherclawv1.RevokePartnerLinkRequest) (
	*pantherclawv1.RevokePartnerLinkResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.Revoke(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokePartnerLinkResponse{Link: h.link(l)}, nil
}

// ListPartnerCustomers implements PartnerServiceHandler.
func (h *Handler) ListPartnerCustomers(ctx context.Context, _ *pantherclawv1.ListPartnerCustomersRequest) (
	*pantherclawv1.ListPartnerCustomersResponse, error,
) {
	cs, err := h.svc.Customers(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPartnerCustomersResponse{}
	for _, c := range cs {
		out.Customers = append(out.Customers, &pantherclawv1.PartnerCustomer{
			CustomerOrgId: c.Org.String(), Name: c.Name, LinkId: c.Link.String(), LinkEndTime: timestamppb.New(c.LinkEndsAt),
			WaitingApprovals: c.WaitingApprovals, OpenAlerts: c.OpenAlerts, LastDecisionTime: ts(c.LastDecisionAt),
			OpenUrl: h.svc.OpenURL(c.Org),
		})
	}
	return out, nil
}

// OpenPartnerSession implements PartnerServiceHandler: over the API it is
// always refused (STEP_UP_REQUIRED); a partner person opens a session on
// the customer's open page with a security key (D1100a).
func (h *Handler) OpenPartnerSession(ctx context.Context, _ *pantherclawv1.OpenPartnerSessionRequest) (
	*pantherclawv1.OpenPartnerSessionResponse, error,
) {
	return nil, h.svc.OpenOverAPI(ctx)
}

// GetCurrentPartnerSession implements PartnerServiceHandler.
func (h *Handler) GetCurrentPartnerSession(ctx context.Context, _ *pantherclawv1.GetCurrentPartnerSessionRequest) (
	*pantherclawv1.GetCurrentPartnerSessionResponse, error,
) {
	c, err := h.svc.CurrentSession(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetCurrentPartnerSessionResponse{
		SessionId: c.Session.String(), LinkId: c.Link.String(), PartnerOrgId: c.PartnerOrg.String(),
		PartnerUserId: c.User.String(), Scopes: scopes(c.Scopes), ExpireTime: timestamppb.New(c.ExpiresAt),
	}, nil
}

// ProposeRollout implements PartnerServiceHandler.
func (h *Handler) ProposeRollout(ctx context.Context, req *pantherclawv1.ProposeRolloutRequest) (
	*pantherclawv1.ProposeRolloutResponse, error,
) {
	in := partners.NewProposal{Kind: kindName[req.GetKind()], Title: req.GetTitle(), Body: req.GetBody()}
	for _, s := range req.GetCustomerOrgIds() {
		id, err := idOf(s)
		if err != nil {
			return nil, err
		}
		in.Customers = append(in.Customers, id)
	}
	ps, template, err := h.svc.Propose(ctx, in)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ProposeRolloutResponse{}
	if !template.IsZero() {
		out.TemplateId = template.String()
	}
	for _, p := range ps {
		p.Body = nil
		out.Proposals = append(out.Proposals, proposal(p))
	}
	return out, nil
}

// ListPartnerProposals implements PartnerServiceHandler.
func (h *Handler) ListPartnerProposals(ctx context.Context, req *pantherclawv1.ListPartnerProposalsRequest) (
	*pantherclawv1.ListPartnerProposalsResponse, error,
) {
	ps, next, err := h.svc.ListProposals(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPartnerProposalsResponse{NextPageToken: next}
	for _, p := range ps {
		out.Proposals = append(out.Proposals, proposal(p))
	}
	return out, nil
}

// GetPartnerProposal implements PartnerServiceHandler.
func (h *Handler) GetPartnerProposal(ctx context.Context, req *pantherclawv1.GetPartnerProposalRequest) (
	*pantherclawv1.GetPartnerProposalResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.GetProposal(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPartnerProposalResponse{Proposal: proposal(p)}, nil
}

// AcceptPartnerProposal implements PartnerServiceHandler.
func (h *Handler) AcceptPartnerProposal(ctx context.Context, req *pantherclawv1.AcceptPartnerProposalRequest) (
	*pantherclawv1.AcceptPartnerProposalResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.Accept(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Body = nil
	return &pantherclawv1.AcceptPartnerProposalResponse{Proposal: proposal(p)}, nil
}

// DeclinePartnerProposal implements PartnerServiceHandler.
func (h *Handler) DeclinePartnerProposal(ctx context.Context, req *pantherclawv1.DeclinePartnerProposalRequest) (
	*pantherclawv1.DeclinePartnerProposalResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.Decline(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	p.Body = nil
	return &pantherclawv1.DeclinePartnerProposalResponse{Proposal: proposal(p)}, nil
}

// WithdrawPartnerProposal implements PartnerServiceHandler.
func (h *Handler) WithdrawPartnerProposal(ctx context.Context, req *pantherclawv1.WithdrawPartnerProposalRequest) (
	*pantherclawv1.WithdrawPartnerProposalResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.Withdraw(ctx, id)
	if err != nil {
		return nil, err
	}
	p.Body = nil
	return &pantherclawv1.WithdrawPartnerProposalResponse{Proposal: proposal(p)}, nil
}
