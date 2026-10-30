// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rulesrpc serves ConsequenceRuleService over Connect (G0 M17
// D112). Handlers only translate; the use cases check the caller.
package rulesrpc

import (
	"context"
	"encoding/hex"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/consequencerules"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/protect"
)

// Handler serves ConsequenceRuleService.
type Handler struct {
	pantherclawv1connect.UnimplementedConsequenceRuleServiceHandler
	svc *consequencerules.Service
}

// New returns the ConsequenceRuleService handler.
func New(svc *consequencerules.Service) *Handler { return &Handler{svc: svc} }

// Rule is the stored form of a spec.
func Rule(s *pantherclawv1.ConsequenceRuleSpec) defs.ConsequenceRule {
	c := s.GetConsequence()
	return defs.ConsequenceRule{
		ID: s.GetId(), Operation: s.GetOperation(), When: s.GetWhen(), RequiresFacts: s.GetRequiresFacts(),
		Consequence: defs.Consequence{
			Operation: c.GetOperation(), Effect: c.GetEffect(), Description: c.GetDescription(), Target: c.GetTarget(),
			Environments: c.GetEnvironments(),
		},
		ValidUntil: s.GetValidUntil(), MaxDepth: int(s.GetMaxDepth()),
	}
}

// Spec is a rule as its author wrote it.
func Spec(r defs.ConsequenceRule) *pantherclawv1.ConsequenceRuleSpec {
	return &pantherclawv1.ConsequenceRuleSpec{
		Id: r.ID, Operation: r.Operation, When: r.When, RequiresFacts: r.RequiresFacts,
		Consequence: &pantherclawv1.ConsequenceSpec{
			Operation: r.Consequence.Operation, Effect: r.Consequence.Effect, Description: r.Consequence.Description,
			Target: r.Consequence.Target, Environments: r.Consequence.Environments,
		},
		ValidUntil: r.ValidUntil, MaxDepth: int32(r.MaxDepth), //nolint:gosec // 0..4
	}
}

func versionPB(v consequencerules.Version) *pantherclawv1.ConsequenceRuleVersion {
	out := &pantherclawv1.ConsequenceRuleVersion{
		Id: v.ID.String(), Rule: Spec(v.Rule), Version: v.Version, Digest: hex.EncodeToString(v.Digest), State: v.State,
		ProposedBy: v.ProposedBy.String(), CreateTime: timestamppb.New(v.CreatedAt), UpdateTime: timestamppb.New(v.UpdatedAt),
	}
	if v.ApprovedBy != nil {
		out.ApprovedBy = v.ApprovedBy.String()
	}
	return out
}

func pendingPB(p *protect.PendingError) *pantherclawv1.PendingRuleChange {
	if p == nil {
		return nil
	}
	return &pantherclawv1.PendingRuleChange{ProtectedChangeId: p.Change.String(), ChangeRequestId: p.Request.String()}
}

// ProposeConsequenceRule implements ConsequenceRuleServiceHandler.
func (h *Handler) ProposeConsequenceRule(ctx context.Context, r *pantherclawv1.ProposeConsequenceRuleRequest) (
	*pantherclawv1.ProposeConsequenceRuleResponse, error,
) {
	v, held, err := h.svc.Propose(ctx, Rule(r.GetRule()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ProposeConsequenceRuleResponse{Version: versionPB(v), Pending: pendingPB(held)}, nil
}

// RetireConsequenceRule implements ConsequenceRuleServiceHandler.
func (h *Handler) RetireConsequenceRule(ctx context.Context, r *pantherclawv1.RetireConsequenceRuleRequest) (
	*pantherclawv1.RetireConsequenceRuleResponse, error,
) {
	held, err := h.svc.Retire(ctx, r.GetRuleId())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetireConsequenceRuleResponse{Pending: pendingPB(held)}, nil
}

// ListConsequenceRules implements ConsequenceRuleServiceHandler.
func (h *Handler) ListConsequenceRules(ctx context.Context, _ *pantherclawv1.ListConsequenceRulesRequest) (
	*pantherclawv1.ListConsequenceRulesResponse, error,
) {
	vs, err := h.svc.List(ctx, "")
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListConsequenceRulesResponse{}
	for _, v := range vs {
		out.Versions = append(out.Versions, versionPB(v))
	}
	return out, nil
}

// GetConsequenceRule implements ConsequenceRuleServiceHandler.
func (h *Handler) GetConsequenceRule(ctx context.Context, r *pantherclawv1.GetConsequenceRuleRequest) (
	*pantherclawv1.GetConsequenceRuleResponse, error,
) {
	vs, err := h.svc.Get(ctx, r.GetRuleId())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetConsequenceRuleResponse{}
	for _, v := range vs {
		out.Versions = append(out.Versions, versionPB(v))
	}
	return out, nil
}
