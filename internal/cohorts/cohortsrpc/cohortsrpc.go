// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package cohortsrpc serves CohortService over Connect (G0 M11 part 2,
// D40). Handlers only translate; the use cases check the caller.
package cohortsrpc

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/cohorts"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotionsrpc"
)

// Handler serves CohortService.
type Handler struct {
	pantherclawv1connect.UnimplementedCohortServiceHandler
	svc *cohorts.Service
}

// New returns the CohortService handler.
func New(svc *cohorts.Service) *Handler { return &Handler{svc: svc} }

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

func str(id *ids.UUID) string {
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

func cohortPB(c cohorts.Cohort) *pantherclawv1.FleetCohort {
	out := &pantherclawv1.FleetCohort{
		Id: c.ID.String(), Name: c.Name, Description: c.Description, OwnerUserId: c.OwnerUserID.String(), Baseline: c.PcFleetCohort.Baseline,
		StaticMembers: int32(c.StaticMembers), CreatedBy: c.CreatedBy, //nolint:gosec // ≤ 1000
		CreateTime: timestamppb.New(c.CreatedAt), UpdateTime: timestamppb.New(c.UpdatedAt),
	}
	if c.Rule != nil {
		out.Rule = &pantherclawv1.FleetCohortRule{TeamId: str(c.Rule.TeamID), EnvironmentId: str(c.Rule.EnvironmentID), TaskType: c.Rule.TaskType}
	}
	return out
}

func input(in *pantherclawv1.FleetCohortInput) (cohorts.Input, error) {
	owner, err := parse(in.GetOwnerUserId())
	if err != nil {
		return cohorts.Input{}, err
	}
	out := cohorts.Input{Name: in.GetName(), Description: in.GetDescription(), Owner: owner}
	if r := in.GetRule(); r != nil {
		out.Rule = &cohorts.Rule{TaskType: r.GetTaskType()}
		if out.Rule.TeamID, err = optParse(r.GetTeamId()); err != nil {
			return out, err
		}
		if out.Rule.EnvironmentID, err = optParse(r.GetEnvironmentId()); err != nil {
			return out, err
		}
	}
	out.Baseline, err = cohorts.DecodeBaseline(in.GetBaseline())
	return out, err
}

func agentPB(f cohorts.AgentFacts) *pantherclawv1.FleetAgent {
	out := &pantherclawv1.FleetAgent{
		AgentId: f.ID.String(), Name: f.Name, State: f.State, OwnerUserId: str(f.OwnerUserID), EnvironmentId: str(f.EnvironmentID),
		EnvironmentKind: f.EnvironmentKind, TeamId: str(f.TeamID), TaskType: deref(f.TaskType), PromotedOperations: f.Promoted,
		ActiveGrants: f.ActiveGrants, PendingApprovals: f.PendingApprovals,
	}
	if t := f.LastRun(); !t.IsZero() {
		out.LastRunTime = timestamppb.New(t)
	}
	return out
}

func agentsPB(fs []cohorts.AgentFacts) []*pantherclawv1.FleetAgent {
	out := make([]*pantherclawv1.FleetAgent, len(fs))
	for i, f := range fs {
		out[i] = agentPB(f)
	}
	return out
}

// CreateFleetCohort implements CohortServiceHandler.
func (h *Handler) CreateFleetCohort(ctx context.Context, r *pantherclawv1.CreateFleetCohortRequest) (*pantherclawv1.CreateFleetCohortResponse, error) {
	in, err := input(r.GetCohort())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateFleetCohortResponse{Cohort: cohortPB(c)}, nil
}

// UpdateFleetCohort implements CohortServiceHandler.
func (h *Handler) UpdateFleetCohort(ctx context.Context, r *pantherclawv1.UpdateFleetCohortRequest) (*pantherclawv1.UpdateFleetCohortResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	in, err := input(r.GetCohort())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.Update(ctx, id, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateFleetCohortResponse{Cohort: cohortPB(c)}, nil
}

// DeleteFleetCohort implements CohortServiceHandler.
func (h *Handler) DeleteFleetCohort(ctx context.Context, r *pantherclawv1.DeleteFleetCohortRequest) (*pantherclawv1.DeleteFleetCohortResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DeleteFleetCohortResponse{}, h.svc.Delete(ctx, id)
}

// GetFleetCohort implements CohortServiceHandler.
func (h *Handler) GetFleetCohort(ctx context.Context, r *pantherclawv1.GetFleetCohortRequest) (*pantherclawv1.GetFleetCohortResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetFleetCohortResponse{Cohort: cohortPB(c)}, nil
}

// ListFleetCohorts implements CohortServiceHandler.
func (h *Handler) ListFleetCohorts(ctx context.Context, r *pantherclawv1.ListFleetCohortsRequest) (*pantherclawv1.ListFleetCohortsResponse, error) {
	cs, next, err := h.svc.List(ctx, r.GetPageToken(), int(r.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFleetCohortsResponse{NextPageToken: next}
	for _, c := range cs {
		out.Cohorts = append(out.Cohorts, cohortPB(c))
	}
	return out, nil
}

// ListFleetCohortMembers implements CohortServiceHandler.
func (h *Handler) ListFleetCohortMembers(ctx context.Context, r *pantherclawv1.ListFleetCohortMembersRequest,
) (*pantherclawv1.ListFleetCohortMembersResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	after, err := optParse(r.GetPageToken())
	if err != nil {
		return nil, err
	}
	ms, hidden, next, err := h.svc.Members(ctx, id, after, int(r.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListFleetCohortMembersResponse{Hidden: int32(hidden), NextPageToken: str(next)} //nolint:gosec // ≤ 201
	for _, m := range ms {
		out.Members = append(out.Members, &pantherclawv1.FleetCohortMember{
			AgentId: m.Agent.ID.String(), Name: m.Agent.Name, State: m.Agent.State, StaticMember: m.Static,
		})
	}
	return out, nil
}

func (h *Handler) change(ctx context.Context, cohort string, agents []string, remove bool) (int32, error) {
	id, err := parse(cohort)
	if err != nil {
		return 0, err
	}
	as, err := parseAll(agents)
	if err != nil {
		return 0, err
	}
	n, err := h.svc.ChangeMembers(ctx, id, as, remove)
	return int32(n), err //nolint:gosec // ≤ 1000
}

// AddFleetCohortMembers implements CohortServiceHandler.
func (h *Handler) AddFleetCohortMembers(ctx context.Context, r *pantherclawv1.AddFleetCohortMembersRequest,
) (*pantherclawv1.AddFleetCohortMembersResponse, error) {
	n, err := h.change(ctx, r.GetCohortId(), r.GetAgentIds(), false)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AddFleetCohortMembersResponse{Changed: n}, nil
}

// RemoveFleetCohortMembers implements CohortServiceHandler.
func (h *Handler) RemoveFleetCohortMembers(ctx context.Context, r *pantherclawv1.RemoveFleetCohortMembersRequest,
) (*pantherclawv1.RemoveFleetCohortMembersResponse, error) {
	n, err := h.change(ctx, r.GetCohortId(), r.GetAgentIds(), true)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RemoveFleetCohortMembersResponse{Changed: n}, nil
}

// SetAgentTaskType implements CohortServiceHandler.
func (h *Handler) SetAgentTaskType(ctx context.Context, r *pantherclawv1.SetAgentTaskTypeRequest) (*pantherclawv1.SetAgentTaskTypeResponse, error) {
	id, err := parse(r.GetAgentId())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetAgentTaskTypeResponse{}, h.svc.SetAgentTaskType(ctx, id, r.GetTaskType())
}

// GetCohortQueue implements CohortServiceHandler.
func (h *Handler) GetCohortQueue(ctx context.Context, r *pantherclawv1.GetCohortQueueRequest) (*pantherclawv1.GetCohortQueueResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	q, err := h.svc.GetQueue(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetCohortQueueResponse{
		Unowned: agentsPB(q.Unowned), Unpromoted: agentsPB(q.Unpromoted), PendingApprovals: agentsPB(q.Pending),
		Hidden: int32(q.Hidden), Notes: q.Notes, //nolint:gosec // ≤ 2000
	}
	for _, d := range q.OverBaseline {
		out.OverBaseline = append(out.OverBaseline, &pantherclawv1.BaselineDeparture{GrantId: d.Grant.String(), AgentId: d.Agent.String(), Reason: d.Reason})
	}
	return out, nil
}

// GetCohortChanges implements CohortServiceHandler.
func (h *Handler) GetCohortChanges(ctx context.Context, r *pantherclawv1.GetCohortChangesRequest) (*pantherclawv1.GetCohortChangesResponse, error) {
	id, err := parse(r.GetCohortId())
	if err != nil {
		return nil, err
	}
	var since time.Time
	if r.GetSince() != nil {
		since = r.GetSince().AsTime()
	}
	ch, err := h.svc.GetChanges(ctx, id, since)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetCohortChangesResponse{Since: timestamppb.New(ch.Since), Hidden: int32(ch.Hidden)} //nolint:gosec // ≤ 2000
	add := func(kind string, at time.Time, agent, subject, actor, detail string) {
		out.Changes = append(out.Changes, &pantherclawv1.CohortChange{
			Kind: kind, Time: timestamppb.New(at), AgentId: agent, SubjectId: subject, Actor: actor, Detail: detail,
		})
	}
	for _, m := range ch.MembersAdded {
		add("MEMBER_ADDED", m.AddedAt, m.AgentID.String(), "", m.AddedBy, "")
	}
	for _, g := range ch.GrantRevisions {
		kind, detail := "GRANT_REVISED", fmt.Sprintf("revision %d", g.Revision)
		if g.Revision == 1 {
			kind, detail = "GRANT_ISSUED", ""
		} else if g.Widens {
			detail += ", widens"
		}
		add(kind, g.CreatedAt, g.AgentID.String(), g.GrantID.String(), g.CreatedBy, detail)
	}
	for _, g := range ch.GrantRevoked {
		add("GRANT_REVOKED", g.RevokedAt, g.AgentID.String(), g.ID.String(), "", g.Reason)
	}
	for _, v := range ch.PolicyVersions {
		add("POLICY_PUBLISHED", v.PublishedAt, "", v.ID.String(), "", fmt.Sprintf("%s v%d", v.BundleID, v.Version))
	}
	for _, p := range ch.PackageVersions {
		add("PACKAGE_ACTIVATED", p.ChangedAt, "", p.Name+"@"+p.Version, "", "")
	}
	for _, p := range ch.Promotions {
		pr := promotions.Promotion{PcAgentPromotion: p}
		_ = json.Unmarshal(p.Checks, &pr.Checks) // written by promotions
		out.Promotions = append(out.Promotions, promotionsrpc.PromotionPB(pr))
		if !p.PromotedAt.Before(ch.Since) {
			add("PROMOTED", p.PromotedAt, p.AgentID.String(), p.ID.String(), p.PromotedBy.String(), p.Operation)
		}
		if p.RevokedAt != nil && !p.RevokedAt.Before(ch.Since) {
			add("PROMOTION_REVOKED", *p.RevokedAt, p.AgentID.String(), p.ID.String(), str(p.RevokedBy), p.Operation)
		}
	}
	slices.SortStableFunc(out.Changes, func(a, b *pantherclawv1.CohortChange) int {
		return cmp.Compare(a.GetTime().AsTime().UnixNano(), b.GetTime().AsTime().UnixNano())
	})
	return out, nil
}

// GetFleetOverview implements CohortServiceHandler.
func (h *Handler) GetFleetOverview(ctx context.Context, r *pantherclawv1.GetFleetOverviewRequest) (*pantherclawv1.GetFleetOverviewResponse, error) {
	after, err := optParse(r.GetPageToken())
	if err != nil {
		return nil, err
	}
	o, err := h.svc.GetFleetOverview(ctx, after, int(r.GetPageSize()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetFleetOverviewResponse{Agents: agentsPB(o.Agents), Hidden: int32(o.Hidden), NextPageToken: str(o.Next)}, nil //nolint:gosec // ≤ 200
}
