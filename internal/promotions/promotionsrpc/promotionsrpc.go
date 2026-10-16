// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package promotionsrpc serves PromotionService over Connect (G0 M11 part
// 2, D39). Handlers only translate: authentication, the coarse permission
// check and protovalidate have run before a handler is called, and the use
// cases check the caller again.
package promotionsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions"
)

// Handler serves PromotionService.
type Handler struct {
	pantherclawv1connect.UnimplementedPromotionServiceHandler
	svc *promotions.Service
}

// New returns the PromotionService handler.
func New(svc *promotions.Service) *Handler { return &Handler{svc: svc} }

var errID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "an id is not a UUID")

func parse(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errID
	}
	return id, nil
}

func optParse(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil
	}
	id, err := parse(s)
	return &id, err
}

var behaviors = map[string]pantherclawv1.FailureBehavior{
	promotions.FailClosed:      pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_FAIL_CLOSED,
	promotions.Queue:           pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_QUEUE,
	promotions.DegradeReadOnly: pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_DEGRADE_READ_ONLY,
}

func behaviorOf(b pantherclawv1.FailureBehavior) string {
	for k, v := range behaviors {
		if v == b {
			return k
		}
	}
	return ""
}

var states = map[string]pantherclawv1.PromotionState{
	promotions.StateActive:      pantherclawv1.PromotionState_PROMOTION_STATE_ACTIVE,
	promotions.StateRevoked:     pantherclawv1.PromotionState_PROMOTION_STATE_REVOKED,
	promotions.StateProvisional: pantherclawv1.PromotionState_PROMOTION_STATE_PROVISIONAL,
	promotions.StateExpired:     pantherclawv1.PromotionState_PROMOTION_STATE_EXPIRED,
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func checksPB(cs []promotions.Check) []*pantherclawv1.PromotionCheck {
	out := make([]*pantherclawv1.PromotionCheck, len(cs))
	for i, c := range cs {
		out[i] = &pantherclawv1.PromotionCheck{Name: c.Name, Passed: c.Passed, Detail: c.Detail, Pending: c.Pending}
	}
	return out
}

// PromotionPB is a promotion as the API returns it.
func PromotionPB(p promotions.Promotion) *pantherclawv1.Promotion {
	out := &pantherclawv1.Promotion{
		Id: p.ID.String(), AgentId: p.AgentID.String(), EnvironmentId: p.EnvironmentID.String(), Operation: p.Operation,
		State: states[p.State], Checks: checksPB(p.Checks), FailureBehavior: behaviors[p.FailureBehavior],
		PromotedBy: p.PromotedBy.String(), CredentialId: p.CredentialID.String(), PromoteTime: timestamppb.New(p.PromotedAt),
		RevokeTime: ts(p.RevokedAt), ExpireTime: ts(p.ExpiresAt), ConfirmTime: ts(p.ConfirmedAt), ExpiredTime: ts(p.ExpiredAt),
	}
	if p.RevokedBy != nil {
		out.RevokedBy = p.RevokedBy.String()
	}
	if p.RevokeReason != nil {
		out.RevokeReason = *p.RevokeReason
	}
	return out
}

func promotionsPB(ps []promotions.Promotion) []*pantherclawv1.Promotion {
	out := make([]*pantherclawv1.Promotion, len(ps))
	for i, p := range ps {
		out[i] = PromotionPB(p)
	}
	return out
}

func readinessPB(rs []promotions.Readiness) []*pantherclawv1.OperationReadiness {
	out := make([]*pantherclawv1.OperationReadiness, len(rs))
	for i, r := range rs {
		out[i] = &pantherclawv1.OperationReadiness{Operation: r.Operation, Ready: r.Ready(), Provisional: r.Provisional(), Checks: checksPB(r.Checks)}
		if r.Promotion != nil {
			out[i].Promotion = PromotionPB(*r.Promotion)
		}
	}
	return out
}

// PromoteAgent implements PromotionServiceHandler.
func (h *Handler) PromoteAgent(ctx context.Context, r *pantherclawv1.PromoteAgentRequest) (*pantherclawv1.PromoteAgentResponse, error) {
	agent, err := parse(r.GetAgentId())
	if err != nil {
		return nil, err
	}
	env, err := parse(r.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	// A step-up exists only on a browser session, so the API passes none
	// and is refused STEP_UP_REQUIRED; people promote on the promotions
	// page (D53).
	res, err := h.svc.PromoteAgent(ctx, promotions.PromoteInput{
		Agent: agent, Environment: env, Operations: r.GetOperations(), FailureBehavior: behaviorOf(r.GetFailureBehavior()),
	}, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PromoteAgentResponse{
		Promoted: promotionsPB(res.Promoted), Already: promotionsPB(res.Already), Readiness: readinessPB(res.Readiness),
	}, nil
}

// RevokePromotion implements PromotionServiceHandler.
func (h *Handler) RevokePromotion(ctx context.Context, r *pantherclawv1.RevokePromotionRequest) (*pantherclawv1.RevokePromotionResponse, error) {
	id, err := parse(r.GetPromotionId())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.RevokePromotion(ctx, id, r.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokePromotionResponse{Promotion: PromotionPB(p)}, nil
}

// GetReadiness implements PromotionServiceHandler.
func (h *Handler) GetReadiness(ctx context.Context, r *pantherclawv1.GetReadinessRequest) (*pantherclawv1.GetReadinessResponse, error) {
	agent, err := parse(r.GetAgentId())
	if err != nil {
		return nil, err
	}
	env, err := parse(r.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	rs, err := h.svc.GetReadiness(ctx, agent, env, r.GetOperations(), behaviorOf(r.GetFailureBehavior()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetReadinessResponse{Readiness: readinessPB(rs)}, nil
}

// ListPromotions implements PromotionServiceHandler.
func (h *Handler) ListPromotions(ctx context.Context, r *pantherclawv1.ListPromotionsRequest) (*pantherclawv1.ListPromotionsResponse, error) {
	var f promotions.Filter
	var err error
	if f.Agent, err = optParse(r.GetAgentId()); err != nil {
		return nil, err
	}
	if f.Environment, err = optParse(r.GetEnvironmentId()); err != nil {
		return nil, err
	}
	for k, v := range states {
		if v == r.GetState() {
			f.State = k
		}
	}
	after, err := optParse(r.GetPageToken())
	if err != nil {
		return nil, err
	}
	ps, next, err := h.svc.ListPromotions(ctx, f, after, int(r.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPromotionsResponse{Promotions: promotionsPB(ps)}
	if next != nil {
		out.NextPageToken = next.String()
	}
	return out, nil
}
