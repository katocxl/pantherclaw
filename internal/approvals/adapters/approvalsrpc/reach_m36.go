// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package approvalsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Approval reach (G0 M36 D1063..D1065): fatigue, deputies and groups.
// None of these RPCs approves anything.

var errDeputyTimes = pcerr.New(pcerr.InvalidArgument, "DEPUTY_INVALID", "end_time is required")

var fatigueWindows = map[pantherclawv1.FatigueWindow]time.Duration{
	pantherclawv1.FatigueWindow_FATIGUE_WINDOW_HOUR: time.Hour,
	pantherclawv1.FatigueWindow_FATIGUE_WINDOW_DAY:  24 * time.Hour,
	pantherclawv1.FatigueWindow_FATIGUE_WINDOW_WEEK: 7 * 24 * time.Hour,
}

var fatigueRoutings = map[string]pantherclawv1.FatigueRouting{
	app.RoutingRoute: pantherclawv1.FatigueRouting_FATIGUE_ROUTING_ROUTE,
	app.RoutingOff:   pantherclawv1.FatigueRouting_FATIGUE_ROUTING_OFF,
}

func optionalID(s *string) (*ids.UUID, error) {
	if s == nil {
		return nil, nil
	}
	u, err := parseID(*s)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func tsv(t time.Time) *timestamppb.Timestamp { return ts(&t) }

// GetApprovalFatigue implements ApprovalServiceHandler.
func (s *Approvals) GetApprovalFatigue(ctx context.Context, req *pantherclawv1.GetApprovalFatigueRequest) (*pantherclawv1.GetApprovalFatigueResponse, error) {
	decider, err := optionalID(req.DeciderId)
	if err != nil {
		return nil, err
	}
	window, ok := fatigueWindows[req.GetWindow()]
	if !ok {
		return nil, app.ErrFatigueWindow
	}
	f, err := s.svc.GetFatigue(ctx, window, decider)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetApprovalFatigueResponse{Routing: fatigueRoutings[f.Routing], StartTime: tsv(f.Start)}
	for _, d := range f.Deciders {
		p := &pantherclawv1.DeciderFatigue{
			DeciderId: d.Decider.String(), Approvals: d.Approvals, Declines: d.Declines, PeakApprovalsPerHour: d.PeakPerHour,
			MedianSecondsToApprove: d.MedianSeconds, ApproveShare: d.ApproveShare, NightApprovals: d.NightApprovals,
			LongestApprovalStreak: d.LongestStreak,
		}
		for _, fl := range d.Flags {
			p.Flags = append(p.Flags, &pantherclawv1.FatigueFlag{
				Reason: fl.Reason, Approvals: int32(min(fl.Approvals, 1<<30)), //nolint:gosec // bounded
				FlagTime: tsv(fl.Flagged), ClearTime: tsv(fl.ClearsAt),
			})
		}
		out.Deciders = append(out.Deciders, p)
	}
	return out, nil
}

// SetApprovalFatigueRouting implements ApprovalServiceHandler.
func (s *Approvals) SetApprovalFatigueRouting(ctx context.Context, req *pantherclawv1.SetApprovalFatigueRoutingRequest) (
	*pantherclawv1.SetApprovalFatigueRoutingResponse, error,
) {
	routing := ""
	for k, v := range fatigueRoutings {
		if v == req.GetRouting() {
			routing = k
		}
	}
	r, err := s.svc.SetFatigueRouting(ctx, routing)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetApprovalFatigueRoutingResponse{Routing: fatigueRoutings[r]}, nil
}

func deputyProto(d app.Deputy) *pantherclawv1.ApprovalDeputy {
	out := &pantherclawv1.ApprovalDeputy{
		Id: d.ID.String(), PersonId: d.PersonID.String(), DeputyId: d.DeputyID.String(),
		StartTime: tsv(d.StartsAt), EndTime: tsv(d.EndsAt), CreatedBy: d.CreatedBy, CreateTime: tsv(d.CreatedAt),
		State:      pantherclawv1.ApprovalDeputyState(pantherclawv1.ApprovalDeputyState_value["APPROVAL_DEPUTY_STATE_"+d.State]),
		CancelTime: ts(d.CancelledAt),
	}
	if d.CancelledBy != nil {
		out.CancelledBy = *d.CancelledBy
	}
	return out
}

// SetApprovalDeputy implements ApprovalServiceHandler.
func (s *Approvals) SetApprovalDeputy(ctx context.Context, req *pantherclawv1.SetApprovalDeputyRequest) (*pantherclawv1.SetApprovalDeputyResponse, error) {
	person, err := optionalID(req.PersonId)
	if err != nil {
		return nil, err
	}
	deputy, err := parseID(req.GetDeputyId())
	if err != nil {
		return nil, err
	}
	if req.GetEndTime() == nil {
		return nil, errDeputyTimes
	}
	var start time.Time
	if req.GetStartTime() != nil {
		start = req.GetStartTime().AsTime()
	}
	d, err := s.svc.SetDeputy(ctx, person, deputy, start, req.GetEndTime().AsTime())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetApprovalDeputyResponse{Deputy: deputyProto(d)}, nil
}

// CancelApprovalDeputy implements ApprovalServiceHandler.
func (s *Approvals) CancelApprovalDeputy(ctx context.Context, req *pantherclawv1.CancelApprovalDeputyRequest) (*pantherclawv1.CancelApprovalDeputyResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := s.svc.CancelDeputy(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CancelApprovalDeputyResponse{Deputy: deputyProto(d)}, nil
}

// ListApprovalDeputies implements ApprovalServiceHandler.
func (s *Approvals) ListApprovalDeputies(ctx context.Context, req *pantherclawv1.ListApprovalDeputiesRequest) (*pantherclawv1.ListApprovalDeputiesResponse, error) {
	person, err := optionalID(req.PersonId)
	if err != nil {
		return nil, err
	}
	ds, err := s.svc.ListDeputies(ctx, person, req.GetAll(), req.GetIncludeEnded())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListApprovalDeputiesResponse{}
	for _, d := range ds {
		out.Deputies = append(out.Deputies, deputyProto(d))
	}
	return out, nil
}

// ListApprovalGroups implements ApprovalServiceHandler. It reads only.
func (s *Approvals) ListApprovalGroups(ctx context.Context, req *pantherclawv1.ListApprovalGroupsRequest) (*pantherclawv1.ListApprovalGroupsResponse, error) {
	var states []apdomain.State
	for _, st := range req.GetStates() {
		states = append(states, apdomain.State(code(st.String(), "APPROVAL_STATE_")))
	}
	gs, err := s.svc.ListGroups(ctx, code(req.GetGroupBy().String(), "APPROVAL_GROUP_BY_"), states)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListApprovalGroupsResponse{}
	for _, g := range gs {
		p := &pantherclawv1.ApprovalGroup{Key: g.Key, Count: int32(min(g.Count, 1<<30)), BatchEligible: g.BatchEligible} //nolint:gosec // bounded
		for _, id := range g.Requests {
			p.RequestIds = append(p.RequestIds, id.String())
		}
		out.Groups = append(out.Groups, p)
	}
	return out, nil
}
