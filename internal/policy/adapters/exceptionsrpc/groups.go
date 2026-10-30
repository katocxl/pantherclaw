// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package exceptionsrpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
)

// Exception groups (G0 M18 D154; F602, HR-477).

// RequestPolicyExceptionGroup implements PolicyExceptionServiceHandler.
func (h *Handler) RequestPolicyExceptionGroup(ctx context.Context, req *pantherclawv1.RequestPolicyExceptionGroupRequest) (
	*pantherclawv1.RequestPolicyExceptionGroupResponse, error,
) {
	cohort, err := idOf(req.GetCohortId())
	if err != nil {
		return nil, err
	}
	owner, err := optID(req.OwnerId)
	if err != nil {
		return nil, err
	}
	g, cr, err := h.svc.RequestGroup(ctx, exceptions.GroupRequest{
		Rule: req.GetRuleId(), Cohort: cohort, Operations: req.GetOperations(), Reason: req.GetReason(),
		ExpiresIn: time.Duration(req.GetExpiresInSeconds()) * time.Second, Owner: owner,
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestPolicyExceptionGroupResponse{
		Group: GroupProto(g, g.State), ChangeRequestId: cr.ID.String(), ChangeRequestUrl: cr.URL,
	}, nil
}

// GetPolicyExceptionGroup implements PolicyExceptionServiceHandler.
func (h *Handler) GetPolicyExceptionGroup(ctx context.Context, req *pantherclawv1.GetPolicyExceptionGroupRequest) (
	*pantherclawv1.GetPolicyExceptionGroupResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	g, err := h.svc.GetGroup(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetPolicyExceptionGroupResponse{Group: GroupProto(g.Group, g.EffectiveState)}
	for _, a := range g.Agents {
		out.AgentIds = append(out.AgentIds, a.String())
	}
	return out, nil
}

// ListPolicyExceptionGroups implements PolicyExceptionServiceHandler.
func (h *Handler) ListPolicyExceptionGroups(ctx context.Context, req *pantherclawv1.ListPolicyExceptionGroupsRequest) (
	*pantherclawv1.ListPolicyExceptionGroupsResponse, error,
) {
	cohort, err := optID(req.CohortId)
	if err != nil {
		return nil, err
	}
	rows, next, err := h.svc.ListGroups(ctx, exceptions.GroupFilter{Cohort: cohort, State: req.State}, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyExceptionGroupsResponse{NextPageToken: next}
	for _, g := range rows {
		out.Groups = append(out.Groups, GroupProto(g.Group, g.EffectiveState))
	}
	return out, nil
}

// RevokePolicyExceptionGroup implements PolicyExceptionServiceHandler.
func (h *Handler) RevokePolicyExceptionGroup(ctx context.Context, req *pantherclawv1.RevokePolicyExceptionGroupRequest) (
	*pantherclawv1.RevokePolicyExceptionGroupResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	g, err := h.svc.RevokeGroup(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokePolicyExceptionGroupResponse{Group: GroupProto(g, g.State)}, nil
}

// GroupProto renders a group with the state to show.
func GroupProto(g exceptions.Group, state string) *pantherclawv1.PolicyExceptionGroup {
	out := &pantherclawv1.PolicyExceptionGroup{
		Id: g.ID.String(), CohortId: g.CohortID.String(), BundleId: g.BundleID, RuleId: g.RuleID,
		RuleDigest: hex.EncodeToString(g.RuleDigest), Operations: g.Operations, Reason: g.Reason, OwnerId: g.OwnerID.String(),
		RequestedBy: g.RequestedBy.String(), RequestedExpireTime: timestamppb.New(g.RequestedExpiry), State: state,
		Members: g.Members, CreateTime: timestamppb.New(g.CreatedAt),
	}
	if g.ActivatedAt != nil {
		out.ActivateTime = timestamppb.New(*g.ActivatedAt)
	}
	if g.ExpiresAt != nil {
		out.ExpireTime = timestamppb.New(*g.ExpiresAt)
	}
	if g.RevokedBy != nil {
		out.RevokedBy = g.RevokedBy.String()
	}
	if g.RevokedReason != nil {
		out.RevokedReason = *g.RevokedReason
	}
	return out
}
