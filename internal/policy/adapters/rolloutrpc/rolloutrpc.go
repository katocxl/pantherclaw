// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rolloutrpc serves PolicyRolloutService over Connect (G0 M11.1,
// D12, D13). Handlers only translate: authentication, the coarse
// permission check and protovalidate have run before a handler is called,
// and the use cases check the caller again.
package rolloutrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
)

// Handler serves PolicyRolloutService.
type Handler struct {
	pantherclawv1connect.UnimplementedPolicyRolloutServiceHandler
	svc *rollout.Service
}

// New returns the PolicyRolloutService handler.
func New(svc *rollout.Service) *Handler { return &Handler{svc: svc} }

var errID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "an id is not a UUID")

func parse(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errID
	}
	return id, nil
}

func parseAll(xs []string) ([]ids.UUID, error) {
	out := make([]ids.UUID, 0, len(xs))
	for _, x := range xs {
		id, err := parse(x)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

var stages = map[string]pantherclawv1.PolicyRolloutStage{
	rollout.StageShadow:    pantherclawv1.PolicyRolloutStage_POLICY_ROLLOUT_STAGE_SHADOW,
	rollout.StagePilot:     pantherclawv1.PolicyRolloutStage_POLICY_ROLLOUT_STAGE_PILOT,
	rollout.StageComplete:  pantherclawv1.PolicyRolloutStage_POLICY_ROLLOUT_STAGE_COMPLETE,
	rollout.StageCancelled: pantherclawv1.PolicyRolloutStage_POLICY_ROLLOUT_STAGE_CANCELLED, //nolint:misspell // generated name
}

var states = map[string]pantherclawv1.PolicyRolloutTargetState{
	rollout.TargetConfigured:   pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_CONFIGURED,
	rollout.TargetAcknowledged: pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_ACKNOWLEDGED,
	rollout.TargetVerified:     pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_VERIFIED,
	rollout.TargetFailed:       pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_FAILED,
	rollout.TargetException:    pantherclawv1.PolicyRolloutTargetState_POLICY_ROLLOUT_TARGET_STATE_EXCEPTION,
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optString(id *ids.UUID) string {
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

func rolloutPB(r rollout.Rollout) *pantherclawv1.PolicyRollout {
	out := &pantherclawv1.PolicyRollout{
		Id: r.ID.String(), VersionId: r.VersionID.String(), BaseVersionId: optString(r.BaseVersionID), Stage: stages[r.Stage],
		CreatedBy: r.CreatedBy, CreateTime: timestamppb.New(r.CreatedAt), StageChangeTime: timestamppb.New(r.StageChangedAt),
		CompleteTime: ts(r.CompletedAt), TargetCounts: r.Targets,
	}
	for _, c := range r.Cohorts {
		out.Cohorts = append(out.Cohorts, &pantherclawv1.PolicyRolloutCohort{
			CohortId: c.ID.String(), Name: c.Name, Mode: c.Mode, Members: int32(c.Members), //nolint:gosec // ≤ 1000
		})
	}
	return out
}

func targetPB(t dbq.PcPolicyRolloutTarget) *pantherclawv1.PolicyRolloutTarget {
	return &pantherclawv1.PolicyRolloutTarget{
		AgentId: t.AgentID.String(), State: states[t.State], OwnerId: optString(t.OwnerID), Coverage: deref(t.Coverage),
		Reason: deref(t.Reason), UpdateTime: timestamppb.New(t.UpdatedAt),
	}
}

func cohortPB(c rollout.Cohort) *pantherclawv1.PolicyCohort {
	out := &pantherclawv1.PolicyCohort{
		Id: c.ID.String(), Name: c.Name, CreatedBy: c.CreatedBy, CreateTime: timestamppb.New(c.CreatedAt), AgentIds: []string{},
	}
	for _, a := range c.Agents {
		out.AgentIds = append(out.AgentIds, a.String())
	}
	return out
}

func changePB(cr *rollout.ChangeRequest) *pantherclawv1.PolicyChangeRequestRef {
	if cr == nil {
		return nil
	}
	return &pantherclawv1.PolicyChangeRequestRef{Id: cr.ID.String(), Url: cr.URL}
}

// StartPolicyRollout implements PolicyRolloutServiceHandler.
func (h *Handler) StartPolicyRollout(ctx context.Context, r *pantherclawv1.StartPolicyRolloutRequest) (*pantherclawv1.StartPolicyRolloutResponse, error) {
	v, err := parse(r.GetVersionId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.StartRollout(ctx, v, r.GetShadowCohorts())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartPolicyRolloutResponse{Rollout: rolloutPB(out)}, nil
}

// StartPolicyPilot implements PolicyRolloutServiceHandler.
func (h *Handler) StartPolicyPilot(ctx context.Context, r *pantherclawv1.StartPolicyPilotRequest) (*pantherclawv1.StartPolicyPilotResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	out, cr, err := h.svc.StartPilot(ctx, id, r.GetCohorts())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartPolicyPilotResponse{Rollout: rolloutPB(out), ChangeRequest: changePB(cr)}, nil
}

// ExpandPolicyPilot implements PolicyRolloutServiceHandler.
func (h *Handler) ExpandPolicyPilot(ctx context.Context, r *pantherclawv1.ExpandPolicyPilotRequest) (*pantherclawv1.ExpandPolicyPilotResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.ExpandPilot(ctx, id, r.GetCohorts())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ExpandPolicyPilotResponse{Rollout: rolloutPB(out)}, nil
}

// ExcludePolicyRolloutTarget implements PolicyRolloutServiceHandler.
func (h *Handler) ExcludePolicyRolloutTarget(ctx context.Context, r *pantherclawv1.ExcludePolicyRolloutTargetRequest,
) (*pantherclawv1.ExcludePolicyRolloutTargetResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	agent, err := parse(r.GetAgentId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.ExcludeTarget(ctx, id, agent, r.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ExcludePolicyRolloutTargetResponse{Target: targetPB(t)}, nil
}

// CompletePolicyRollout implements PolicyRolloutServiceHandler.
func (h *Handler) CompletePolicyRollout(ctx context.Context, r *pantherclawv1.CompletePolicyRolloutRequest,
) (*pantherclawv1.CompletePolicyRolloutResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	out, cr, err := h.svc.CompleteRollout(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CompletePolicyRolloutResponse{Rollout: rolloutPB(out), ChangeRequest: changePB(cr)}, nil
}

// CancelPolicyRollout implements PolicyRolloutServiceHandler.
func (h *Handler) CancelPolicyRollout(ctx context.Context, r *pantherclawv1.CancelPolicyRolloutRequest) (*pantherclawv1.CancelPolicyRolloutResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.CancelRollout(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CancelPolicyRolloutResponse{Rollout: rolloutPB(out)}, nil
}

// GetPolicyRollout implements PolicyRolloutServiceHandler.
func (h *Handler) GetPolicyRollout(ctx context.Context, r *pantherclawv1.GetPolicyRolloutRequest) (*pantherclawv1.GetPolicyRolloutResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.GetRollout(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPolicyRolloutResponse{Rollout: rolloutPB(out)}, nil
}

// ListPolicyRollouts implements PolicyRolloutServiceHandler.
func (h *Handler) ListPolicyRollouts(ctx context.Context, r *pantherclawv1.ListPolicyRolloutsRequest) (*pantherclawv1.ListPolicyRolloutsResponse, error) {
	limit := int(r.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	rows, err := h.svc.ListRollouts(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyRolloutsResponse{Rollouts: []*pantherclawv1.PolicyRollout{}}
	for _, x := range rows {
		out.Rollouts = append(out.Rollouts, rolloutPB(x))
	}
	return out, nil
}

// ListPolicyRolloutTargets implements PolicyRolloutServiceHandler.
func (h *Handler) ListPolicyRolloutTargets(ctx context.Context, r *pantherclawv1.ListPolicyRolloutTargetsRequest,
) (*pantherclawv1.ListPolicyRolloutTargetsResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	var after ids.UUID
	if r.GetPageToken() != "" {
		if after, err = parse(r.GetPageToken()); err != nil {
			return nil, err
		}
	}
	var state string
	for s, pb := range states {
		if pb == r.GetState() {
			state = s
		}
	}
	limit := int(r.GetPageSize())
	if limit == 0 {
		limit = 100
	}
	rows, err := h.svc.ListTargets(ctx, id, state, after, limit)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyRolloutTargetsResponse{Targets: []*pantherclawv1.PolicyRolloutTarget{}}
	for _, t := range rows {
		out.Targets = append(out.Targets, targetPB(t))
	}
	if len(rows) == limit {
		out.NextPageToken = rows[len(rows)-1].AgentID.String()
	}
	return out, nil
}

// CreatePolicyCohort implements PolicyRolloutServiceHandler.
func (h *Handler) CreatePolicyCohort(ctx context.Context, r *pantherclawv1.CreatePolicyCohortRequest) (*pantherclawv1.CreatePolicyCohortResponse, error) {
	c, err := h.svc.CreateCohort(ctx, r.GetName())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreatePolicyCohortResponse{Cohort: cohortPB(c)}, nil
}

// AddPolicyCohortMembers implements PolicyRolloutServiceHandler.
func (h *Handler) AddPolicyCohortMembers(ctx context.Context, r *pantherclawv1.AddPolicyCohortMembersRequest,
) (*pantherclawv1.AddPolicyCohortMembersResponse, error) {
	agents, err := parseAll(r.GetAgentIds())
	if err != nil {
		return nil, err
	}
	n, err := h.svc.ChangeCohort(ctx, r.GetName(), agents, false)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddPolicyCohortMembersResponse{Added: int32(n)}, nil //nolint:gosec // ≤ 1000
}

// RemovePolicyCohortMembers implements PolicyRolloutServiceHandler.
func (h *Handler) RemovePolicyCohortMembers(ctx context.Context, r *pantherclawv1.RemovePolicyCohortMembersRequest,
) (*pantherclawv1.RemovePolicyCohortMembersResponse, error) {
	agents, err := parseAll(r.GetAgentIds())
	if err != nil {
		return nil, err
	}
	n, err := h.svc.ChangeCohort(ctx, r.GetName(), agents, true)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RemovePolicyCohortMembersResponse{Removed: int32(n)}, nil //nolint:gosec // ≤ 1000
}

// ListPolicyCohorts implements PolicyRolloutServiceHandler.
func (h *Handler) ListPolicyCohorts(ctx context.Context, _ *pantherclawv1.ListPolicyCohortsRequest) (*pantherclawv1.ListPolicyCohortsResponse, error) {
	cs, err := h.svc.ListCohorts(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPolicyCohortsResponse{Cohorts: []*pantherclawv1.PolicyCohort{}}
	for _, c := range cs {
		out.Cohorts = append(out.Cohorts, cohortPB(c))
	}
	return out, nil
}

// GetShadowSummary implements PolicyRolloutServiceHandler.
func (h *Handler) GetShadowSummary(ctx context.Context, r *pantherclawv1.GetShadowSummaryRequest) (*pantherclawv1.GetShadowSummaryResponse, error) {
	id, err := parse(r.GetRolloutId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.GetShadowSummary(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetShadowSummaryResponse{
		Label: s.Label, RolloutId: s.Rollout.String(), Total: s.Total, ByCategory: map[string]int64{}, Truncated: s.Truncated,
		ByDay: []*pantherclawv1.ShadowCount{}, NewlyHeldPerDay: []*pantherclawv1.ShadowCount{}, ByOperation: []*pantherclawv1.ShadowCount{},
		ByAgent: []*pantherclawv1.ShadowCount{}, Samples: []*pantherclawv1.ShadowSample{},
	}
	for c, n := range s.ByCategory {
		out.ByCategory[string(c)] = n
	}
	day := func(xs []rollout.DayCount) []*pantherclawv1.ShadowCount {
		res := []*pantherclawv1.ShadowCount{}
		for _, d := range xs {
			res = append(res, &pantherclawv1.ShadowCount{Key: d.Day, Category: string(d.Category), N: d.N})
		}
		return res
	}
	group := func(xs []rollout.GroupCount) []*pantherclawv1.ShadowCount {
		res := []*pantherclawv1.ShadowCount{}
		for _, g := range xs {
			res = append(res, &pantherclawv1.ShadowCount{Key: g.Key, Category: string(g.Category), N: g.N})
		}
		return res
	}
	out.ByDay, out.NewlyHeldPerDay, out.ByOperation, out.ByAgent = day(s.ByDay), day(s.NewlyHeldPerDay), group(s.ByOperation), group(s.ByAgent)
	for _, x := range s.Samples {
		out.Samples = append(out.Samples, &pantherclawv1.ShadowSample{
			TransactionId: x.Transaction.String(), Evaluation: int32(x.Evaluation), AgentId: x.Agent.String(), Operation: x.Operation, //nolint:gosec // ≤ 64
			OriginalDecision: x.OriginalDecision, OriginalReason: x.OriginalReason, ShadowDecision: x.ShadowDecision,
			ShadowReason: x.ShadowReason, Category: string(x.Category), Limitation: x.Limitation, CreateTime: timestamppb.New(x.At),
		})
	}
	return out, nil
}
