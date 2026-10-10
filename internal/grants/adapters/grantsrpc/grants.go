// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package grantsrpc serves GrantService and GuardrailService over Connect
// (G0 M4 part 2). Bounds, requirements and limits arrive as JSON documents
// and are decoded strictly by the grants domain (HR-100); every permission
// and human-only check is the use case's.
package grantsrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// Grants serves GrantService.
type Grants struct {
	pantherclawv1connect.UnimplementedGrantServiceHandler
	svc *app.Service
}

// NewGrants returns the GrantService handler.
func NewGrants(svc *app.Service) *Grants { return &Grants{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// parseID accepts a UUIDv7, the only kind of id PantherClaw mints.
func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func parseGrantID(s string) (domain.GrantID, error) {
	if _, err := parseID(s); err != nil {
		return domain.GrantID{}, err
	}
	id, err := domain.ParseGrantID(s)
	if err != nil {
		return domain.GrantID{}, errInvalidID
	}
	return id, nil
}

// invalid reports a document the domain refused, with its explanation.
func invalid(err error) error {
	return pcerr.Wrap(err, pcerr.InvalidArgument, "GRANT_INVALID", strings.TrimPrefix(err.Error(), domain.ErrInvalid.Error()+": "))
}

// Terms are the decoded bounds, requirements and limits of a request.
type Terms struct {
	Bounds       domain.Bounds
	Requirements []domain.Requirement
	Limits       domain.Limits
}

// DecodeTerms strictly decodes the three JSON documents of a grant or
// guardrail request. Empty requirements or limits mean none.
func DecodeTerms(bounds, requirements, limits []byte) (Terms, error) {
	var t Terms
	var err error
	if t.Bounds, err = domain.DecodeBounds(bounds); err != nil {
		return Terms{}, invalid(err)
	}
	if t.Requirements, err = domain.DecodeRequirements(requirements); err != nil {
		return Terms{}, invalid(err)
	}
	if len(limits) > 0 {
		if t.Limits, err = domain.DecodeLimits(limits); err != nil {
			return Terms{}, invalid(err)
		}
	}
	return t, nil
}

func principal(a *pantherclawv1.Actor) (domain.Principal, error) {
	kind := domain.PrincipalKind(a.GetKind())
	if kind != domain.PrincipalUser && kind != domain.PrincipalServiceAccount {
		return domain.Principal{}, pcerr.New(pcerr.InvalidArgument, "PRINCIPAL_INVALID", `the principal is a "user" or a "service_account"`)
	}
	id, err := parseID(a.GetId())
	if err != nil {
		return domain.Principal{}, err
	}
	return domain.Principal{Kind: kind, ID: id}, nil
}

func delegation(d *pantherclawv1.GrantDelegation) domain.Delegation {
	return domain.Delegation{Depth: int(d.GetDepth()), MaxChildren: int(d.GetMaxChildren())}
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func actor(p domain.Principal) *pantherclawv1.Actor {
	if p.ID.IsZero() {
		return nil
	}
	return &pantherclawv1.Actor{Kind: string(p.Kind), Id: p.ID.String()}
}

var grantStates = map[domain.State]pantherclawv1.GrantState{
	domain.StateActive:  pantherclawv1.GrantState_GRANT_STATE_ACTIVE,
	domain.StateRevoked: pantherclawv1.GrantState_GRANT_STATE_REVOKED,
}

// GrantProto renders a grant revision. The documents are the canonical
// encodings the server stores.
func GrantProto(g domain.Grant) (*pantherclawv1.Grant, error) {
	enc, err := encodeTerms(g.Bounds, g.Requirements, g.Limits)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.Grant{
		Id: g.ID.String(), Revision: int32(g.Revision), State: grantStates[g.State], AgentId: g.AgentID.String(), //nolint:gosec // small
		Principal: actor(g.Principal), EnvironmentId: g.EnvironmentID.String(), TaskRef: g.TaskRef,
		StartTime: ts(g.NotBefore), ExpireTime: ts(g.ExpiresAt), Bounds: enc.bounds, Requirements: enc.requirements, Limits: enc.limits,
		Delegation: &pantherclawv1.GrantDelegation{
			Depth: int32(g.Delegation.Depth), MaxChildren: int32(g.Delegation.MaxChildren), //nolint:gosec // validated
		},
		MinAttestationLevel: int32(g.MinAttestation), Depth: int32(g.Depth), //nolint:gosec // 0..4
		Grantor: actor(g.Grantor), Basis: g.Basis, CreateTime: ts(g.RevisedAt),
	}
	if !g.InstanceID.IsZero() {
		out.InstanceId = g.InstanceID.String()
	}
	if !g.Parent.IsZero() {
		out.ParentGrantId = g.Parent.String()
	}
	return out, nil
}

// IssueGrant implements GrantServiceHandler.
func (s *Grants) IssueGrant(ctx context.Context, req *pantherclawv1.IssueGrantRequest) (*pantherclawv1.IssueGrantResponse, error) {
	agent, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	p, err := principal(req.GetPrincipal())
	if err != nil {
		return nil, err
	}
	t, err := DecodeTerms(req.GetBounds(), req.GetRequirements(), req.GetLimits())
	if err != nil {
		return nil, err
	}
	in := app.IssueRequest{
		AgentID: agent, Principal: p, TaskRef: req.GetTaskRef(), ExpiresAt: req.GetExpireTime().AsTime(),
		Bounds: t.Bounds, Requirements: t.Requirements, Limits: t.Limits, Delegation: delegation(req.GetDelegation()),
		MinAttestation: int(req.GetMinAttestationLevel()),
	}
	if req.InstanceId != nil {
		if in.InstanceID, err = parseID(req.GetInstanceId()); err != nil {
			return nil, err
		}
	}
	if req.GetStartTime() != nil {
		in.NotBefore = req.GetStartTime().AsTime()
	}
	g, err := s.svc.Issue(ctx, in)
	if err != nil {
		return nil, err
	}
	out, err := GrantProto(g)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.IssueGrantResponse{Grant: out}, nil
}

// ReviseGrant implements GrantServiceHandler.
func (s *Grants) ReviseGrant(ctx context.Context, req *pantherclawv1.ReviseGrantRequest) (*pantherclawv1.ReviseGrantResponse, error) {
	id, err := parseGrantID(req.GetId())
	if err != nil {
		return nil, err
	}
	t, err := DecodeTerms(req.GetBounds(), req.GetRequirements(), req.GetLimits())
	if err != nil {
		return nil, err
	}
	in := app.ReviseRequest{
		ID: id, Revision: int(req.GetRevision()), TaskRef: req.GetTaskRef(),
		Bounds: t.Bounds, Requirements: t.Requirements, Limits: t.Limits, Delegation: delegation(req.GetDelegation()),
		MinAttestation: int(req.GetMinAttestationLevel()),
	}
	if req.GetExpireTime() != nil {
		in.ExpiresAt = req.GetExpireTime().AsTime()
	}
	if req.AccessRequestId != nil {
		if in.AccessRequest, err = parseID(req.GetAccessRequestId()); err != nil {
			return nil, err
		}
	}
	g, rev, err := s.svc.Revise(ctx, in)
	if err != nil {
		return nil, err
	}
	out, err := GrantProto(g)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ReviseGrantResponse{Grant: out, Widens: rev.Widens}, nil
}

// RevokeGrant implements GrantServiceHandler.
func (s *Grants) RevokeGrant(ctx context.Context, req *pantherclawv1.RevokeGrantRequest) (*pantherclawv1.RevokeGrantResponse, error) {
	id, err := parseGrantID(req.GetId())
	if err != nil {
		return nil, err
	}
	revoked, err := s.svc.Revoke(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeGrantResponse{Revoked: int32(len(revoked))}, nil //nolint:gosec // bounded by fan-out
}

// GetGrant implements GrantServiceHandler.
func (s *Grants) GetGrant(ctx context.Context, req *pantherclawv1.GetGrantRequest) (*pantherclawv1.GetGrantResponse, error) {
	id, err := parseGrantID(req.GetId())
	if err != nil {
		return nil, err
	}
	v, err := s.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetGrantResponse{}
	if out.Grant, err = GrantProto(v.Grant); err != nil {
		return nil, err
	}
	for _, g := range v.Lineage[:len(v.Lineage)-1] {
		p, err := GrantProto(g)
		if err != nil {
			return nil, err
		}
		out.Lineage = append(out.Lineage, p)
	}
	for _, e := range v.Envelopes {
		out.Guardrails = append(out.Guardrails, &pantherclawv1.GuardrailVersion{
			EnvelopeId: e.ID.String(), Revision: int32(e.Revision), Scope: scopeProto(e.Scope), //nolint:gosec // small
		})
	}
	if out.EffectiveBounds, err = domain.EncodeBounds(v.Effective); err != nil {
		return nil, err
	}
	return out, nil
}

var stateFilter = map[pantherclawv1.GrantState]domain.State{
	pantherclawv1.GrantState_GRANT_STATE_ACTIVE:  domain.StateActive,
	pantherclawv1.GrantState_GRANT_STATE_REVOKED: domain.StateRevoked,
}

// ListGrants implements GrantServiceHandler.
func (s *Grants) ListGrants(ctx context.Context, req *pantherclawv1.ListGrantsRequest) (*pantherclawv1.ListGrantsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	f := app.GrantFilter{State: stateFilter[req.GetState()]}
	if req.AgentId != nil {
		id, err := parseID(req.GetAgentId())
		if err != nil {
			return nil, err
		}
		f.AgentID = &id
	}
	if req.ParentGrantId != nil {
		if f.Parent, err = parseGrantID(req.GetParentGrantId()); err != nil {
			return nil, err
		}
	}
	p, err := s.svc.List(ctx, pr, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListGrantsResponse{NextPageToken: p.Next}
	for _, g := range p.Items {
		gp, err := GrantProto(g)
		if err != nil {
			return nil, err
		}
		out.Grants = append(out.Grants, gp)
	}
	return out, nil
}

// GetBudgetState implements GrantServiceHandler.
func (s *Grants) GetBudgetState(ctx context.Context, req *pantherclawv1.GetBudgetStateRequest) (*pantherclawv1.GetBudgetStateResponse, error) {
	id, err := parseGrantID(req.GetGrantId())
	if err != nil {
		return nil, err
	}
	accounts, err := s.svc.BudgetState(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetBudgetStateResponse{}
	for _, a := range accounts {
		b := &pantherclawv1.BudgetAccount{
			OwnerKind: a.OwnerKind, OwnerId: a.OwnerID.String(), Rule: a.Rule, Grouping: a.Grouping, Period: a.Period,
			Currency: a.Currency, Reserved: a.Reserved.String(), Spent: a.Spent.String(),
			MaxCount: a.MaxCount, ReservedCount: a.ReservedCount, SpentCount: a.SpentCount,
		}
		if a.Period != "" && a.Period != "none" {
			b.PeriodStart = ts(a.PeriodStart)
		}
		if a.Limit != nil {
			b.Limit = a.Limit.String()
		}
		if left := a.Available(); left != nil {
			b.Available = left.String()
		}
		out.Accounts = append(out.Accounts, b)
	}
	return out, nil
}

// errGuardrailExists answers CreateEnvelope at a scope that already has a
// guardrail; ReviseEnvelope changes it.
var errGuardrailExists = pcerr.New(pcerr.AlreadyExists, "GUARDRAIL_EXISTS", "the scope already has a guardrail; revise it instead")

func isRevisionChanged(err error) bool { return errors.Is(err, app.ErrRevisionChanged) }
