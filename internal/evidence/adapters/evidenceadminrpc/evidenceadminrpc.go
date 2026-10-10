// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package evidenceadminrpc serves EvidenceAdminService over Connect (G0 M7
// track B, design decision 9, HR-198). Handlers only translate:
// authentication, the coarse permission check and protovalidate have run
// before a handler is called, and the use cases check that the caller is a
// person holding the permission at org scope.
package evidenceadminrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Admin serves EvidenceAdminService.
type Admin struct {
	pantherclawv1connect.UnimplementedEvidenceAdminServiceHandler
	retention *retention.Service
}

// New returns the EvidenceAdminService handler.
func New(r *retention.Service) *Admin { return &Admin{retention: r} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func idString(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var categories = map[retention.Category]pantherclawv1.RetentionCategory{
	retention.Payloads:        pantherclawv1.RetentionCategory_RETENTION_CATEGORY_PAYLOADS,
	retention.NormalizedFacts: pantherclawv1.RetentionCategory_RETENTION_CATEGORY_NORMALIZED_FACTS,
	retention.Receipts:        pantherclawv1.RetentionCategory_RETENTION_CATEGORY_RECEIPTS,
	retention.Approvals:       pantherclawv1.RetentionCategory_RETENTION_CATEGORY_APPROVALS,
	retention.SecurityAudit:   pantherclawv1.RetentionCategory_RETENTION_CATEGORY_SECURITY_AUDIT,
}

func categoryOf(c pantherclawv1.RetentionCategory) (retention.Category, bool) {
	for k, v := range categories {
		if v == c {
			return k, true
		}
	}
	return "", false
}

func revisionProto(r retention.Revision) *pantherclawv1.RetentionRevision {
	return &pantherclawv1.RetentionRevision{
		Revision: int32(r.Number), Days: int32(r.Days), SetBy: idString(r.SetBy), //nolint:gosec // G115: bounded
		CreateTime: ts(r.Created), EffectiveTime: ts(r.Effective),
	}
}

func policyProto(p retention.Policy) *pantherclawv1.RetentionPolicy {
	out := &pantherclawv1.RetentionPolicy{
		Category: categories[p.Category], Current: revisionProto(p.Current),
		MinDays: int32(p.Bounds.Min), MaxDays: int32(p.Bounds.Max), DefaultDays: int32(p.Bounds.Default), //nolint:gosec // G115: ≤ 3650
	}
	if p.Pending != nil {
		out.Pending = revisionProto(*p.Pending)
	}
	return out
}

// GetRetentionPolicies implements EvidenceAdminServiceHandler.
func (a *Admin) GetRetentionPolicies(ctx context.Context, _ *pantherclawv1.GetRetentionPoliciesRequest) (*pantherclawv1.GetRetentionPoliciesResponse, error) {
	ps, err := a.retention.Policies(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetRetentionPoliciesResponse{}
	for _, p := range ps {
		out.Policies = append(out.Policies, policyProto(p))
	}
	return out, nil
}

// SetRetentionPolicy implements EvidenceAdminServiceHandler.
func (a *Admin) SetRetentionPolicy(ctx context.Context, req *pantherclawv1.SetRetentionPolicyRequest) (*pantherclawv1.SetRetentionPolicyResponse, error) {
	c, ok := categoryOf(req.GetCategory())
	if !ok {
		return nil, retention.ErrCategory
	}
	ch, err := a.retention.SetPolicy(ctx, c, int(req.GetDays()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetRetentionPolicyResponse{Policy: policyProto(ch.Policy), Changed: ch.Changed, Shortened: ch.Shortened}, nil
}

var scopes = map[retention.HoldScope]pantherclawv1.LegalHoldScope{
	retention.ScopeOrg:         pantherclawv1.LegalHoldScope_LEGAL_HOLD_SCOPE_ORG,
	retention.ScopeAgent:       pantherclawv1.LegalHoldScope_LEGAL_HOLD_SCOPE_AGENT,
	retention.ScopeRun:         pantherclawv1.LegalHoldScope_LEGAL_HOLD_SCOPE_RUN,
	retention.ScopeTransaction: pantherclawv1.LegalHoldScope_LEGAL_HOLD_SCOPE_TRANSACTION,
	retention.ScopeTimeRange:   pantherclawv1.LegalHoldScope_LEGAL_HOLD_SCOPE_TIME_RANGE,
}

var holdStates = map[string]pantherclawv1.LegalHoldState{
	retention.HoldActive:   pantherclawv1.LegalHoldState_LEGAL_HOLD_STATE_ACTIVE,
	retention.HoldReleased: pantherclawv1.LegalHoldState_LEGAL_HOLD_STATE_RELEASED,
}

func holdProto(h retention.Hold) *pantherclawv1.LegalHold {
	return &pantherclawv1.LegalHold{
		Id: h.ID.String(), Scope: scopes[retention.HoldScope(h.Scope)], ScopeId: idString(h.ScopeID),
		StartTime: tsp(h.RangeStart), EndTime: tsp(h.RangeEnd), Reason: h.Reason, State: holdStates[h.State],
		CreatedBy: h.CreatedBy.String(), CreateTime: ts(h.CreatedAt), ReleasedBy: idString(h.ReleasedBy),
		ReleaseTime: tsp(h.ReleasedAt), ReleaseReason: deref(h.ReleaseReason),
	}
}

// CreateLegalHold implements EvidenceAdminServiceHandler.
func (a *Admin) CreateLegalHold(ctx context.Context, req *pantherclawv1.CreateLegalHoldRequest) (*pantherclawv1.CreateLegalHoldResponse, error) {
	h := retention.HoldRequest{Reason: req.GetReason()}
	for k, v := range scopes {
		if v == req.GetScope() {
			h.Scope = k
		}
	}
	if req.ScopeId != nil {
		id, err := ids.ParseUUID(req.GetScopeId())
		if err != nil {
			return nil, errInvalidID
		}
		h.ID = &id
	}
	if req.StartTime != nil {
		s := req.GetStartTime().AsTime()
		h.Start = &s
	}
	if req.EndTime != nil {
		e := req.GetEndTime().AsTime()
		h.End = &e
	}
	out, err := a.retention.CreateHold(ctx, h)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateLegalHoldResponse{Hold: holdProto(out)}, nil
}

// ReleaseLegalHold implements EvidenceAdminServiceHandler.
func (a *Admin) ReleaseLegalHold(ctx context.Context, req *pantherclawv1.ReleaseLegalHoldRequest) (*pantherclawv1.ReleaseLegalHoldResponse, error) {
	id, err := ids.ParseUUID(req.GetId())
	if err != nil {
		return nil, errInvalidID
	}
	out, err := a.retention.ReleaseHold(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ReleaseLegalHoldResponse{Hold: holdProto(out)}, nil
}

// ListLegalHolds implements EvidenceAdminServiceHandler.
func (a *Admin) ListLegalHolds(ctx context.Context, req *pantherclawv1.ListLegalHoldsRequest) (*pantherclawv1.ListLegalHoldsResponse, error) {
	state := ""
	for k, v := range holdStates {
		if v == req.GetState() {
			state = k
		}
	}
	p, err := a.retention.ListHolds(ctx, state, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListLegalHoldsResponse{NextPageToken: p.Next}
	for _, h := range p.Items {
		out.Holds = append(out.Holds, holdProto(h))
	}
	return out, nil
}
