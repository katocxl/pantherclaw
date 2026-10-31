// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package investigationsrpc serves InvestigationService over Connect (G0
// M10 D20).
package investigationsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/investigations"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves InvestigationService.
type Handler struct {
	pantherclawv1connect.UnimplementedInvestigationServiceHandler
	svc *investigations.Service
}

// New returns the InvestigationService handler.
func New(svc *investigations.Service) *Handler { return &Handler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func str(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func party(p *investigations.Party) *pantherclawv1.InvestigationParty {
	if p == nil {
		return nil
	}
	return &pantherclawv1.InvestigationParty{Kind: p.Kind, Id: p.ID.String()}
}

func rangeOf(start, end *timestamppb.Timestamp) investigations.Range {
	var r investigations.Range
	if start != nil {
		r.Start = start.AsTime()
	}
	if end != nil {
		r.End = end.AsTime()
	}
	return r
}

// WhatHappened implements InvestigationServiceHandler.
func (h *Handler) WhatHappened(ctx context.Context, req *pantherclawv1.WhatHappenedRequest) (*pantherclawv1.WhatHappenedResponse, error) {
	id, err := idOf(req.GetTransactionId())
	if err != nil {
		return nil, err
	}
	x, err := h.svc.WhatHappened(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.WhatHappenedResponse{
		TransactionId: x.Transaction.String(), RunId: x.Run.String(), AgentId: x.Agent.String(), Operation: x.Operation,
		Decision: x.Decision, Reason: x.Reason, Allowed: x.Allowed, Held: x.Held, Denied: x.Denied, Observed: x.Observed,
		Dispatched: x.Dispatched, EffectConfirmed: x.EffectConfirmed, Outcome: x.Outcome, Effect: x.Effect,
		Launcher: party(x.Launcher), Principal: party(x.Principal), ScopeLimited: x.ScopeLimited,
		CreateTime: timestamppb.New(x.Created), ConnectionId: str(x.Connection), DestinationClass: x.DestinationClass,
	}
	for _, g := range x.Grantors {
		out.Grantors = append(out.Grantors, &pantherclawv1.InvestigationGrantor{
			GrantId: g.Grant.String(), AgentId: g.Agent.String(), Grantor: party(&g.Grantor), Principal: party(g.Principal),
			Depth: int32(g.Depth), State: g.State, CreateTime: timestamppb.New(g.Created), RevokeTime: ts(g.Revoked), //nolint:gosec // G115: depth ≤ 4
		})
	}
	out.Delegation = delegations(x.Delegation)
	for _, a := range x.Approvals {
		out.Approvals = append(out.Approvals, approval(a))
	}
	return out, nil
}

// GetRunTimeline implements InvestigationServiceHandler.
func (h *Handler) GetRunTimeline(ctx context.Context, req *pantherclawv1.GetRunTimelineRequest) (*pantherclawv1.GetRunTimelineResponse, error) {
	id, err := idOf(req.GetRunId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.RunTimeline(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetRunTimelineResponse{
		RunId: t.Run.String(), AgentId: t.Agent.String(), State: t.State, StartTime: timestamppb.New(t.Start),
		EndTime: ts(t.End), Truncated: t.Truncated, ScopeLimited: t.ScopeLimited,
	}
	for _, e := range t.Events {
		out.Events = append(out.Events, event(e))
	}
	for _, g := range t.Gaps {
		out.Gaps = append(out.Gaps, gap(g))
	}
	for _, l := range t.Lanes {
		out.Lanes = append(out.Lanes, lane(l))
	}
	for _, p := range t.Phases {
		out.Phases = append(out.Phases, phase(p))
	}
	return out, nil
}

// GetPrecedingContext implements InvestigationServiceHandler.
func (h *Handler) GetPrecedingContext(ctx context.Context, req *pantherclawv1.GetPrecedingContextRequest) (
	*pantherclawv1.GetPrecedingContextResponse, error,
) {
	var run ids.UUID
	var txn *ids.UUID
	var err error
	switch {
	case req.TransactionId != nil:
		id, err := idOf(req.GetTransactionId())
		if err != nil {
			return nil, err
		}
		txn = &id
	case req.RunId != nil:
		if run, err = idOf(req.GetRunId()); err != nil {
			return nil, err
		}
	default:
		return nil, errInvalidID
	}
	p, err := h.svc.PrecedingContext(ctx, run, txn, rangeOf(req.GetStartTime(), req.GetEndTime()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetPrecedingContextResponse{
		RunId: p.Run.String(), AgentId: p.Agent.String(), TransactionId: str(p.Transaction),
		StartTime: timestamppb.New(p.Range.Start), EndTime: timestamppb.New(p.Range.End),
		ContentProvenance: p.ContentProvenance, ScopeLimited: p.ScopeLimited,
	}
	for _, a := range p.Authority {
		out.Items = append(out.Items, &pantherclawv1.ContextItem{
			Kind: "AUTHORITY", Time: timestamppb.New(a.At), Change: a.Change, GrantId: a.Grant.String(),
			Detail: a.Grantor.Kind + ":" + a.Grantor.ID.String(), Basis: string(a.Basis),
		})
	}
	for _, t := range p.Tools {
		out.Items = append(out.Items, &pantherclawv1.ContextItem{
			Kind: "TOOL", Time: timestamppb.New(t.At), Change: t.Change, ConnectionId: t.Connection.String(),
			Detail: t.Package, Basis: string(t.Basis),
		})
	}
	for _, s := range p.Shared {
		out.Items = append(out.Items, &pantherclawv1.ContextItem{
			Kind: "SHARED", Time: timestamppb.New(s.First), ConnectionId: str(s.Connection), RunId: s.Run.String(),
			AgentId: s.Agent.String(), Detail: s.TargetType + ":" + s.TargetID, Actions: s.Actions, Basis: string(s.Basis),
		})
	}
	for _, l := range p.Links {
		out.Items = append(out.Items, &pantherclawv1.ContextItem{
			Kind: "LINK", Time: timestamppb.New(l.At), Change: l.Kind, ConnectionId: str(l.Connection), RunId: p.Run.String(),
			TransactionId: l.From.String(), Detail: l.Operation, Basis: string(l.Basis), Explanation: l.Explanation,
		})
	}
	return out, nil
}

// CompareRun implements InvestigationServiceHandler.
func (h *Handler) CompareRun(ctx context.Context, req *pantherclawv1.CompareRunRequest) (*pantherclawv1.CompareRunResponse, error) {
	id, err := idOf(req.GetRunId())
	if err != nil {
		return nil, err
	}
	c, err := h.svc.CompareRun(ctx, id, rangeOf(req.GetStartTime(), req.GetEndTime()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.CompareRunResponse{
		RunId: c.Run.String(), AgentId: c.Agent.String(), StartTime: timestamppb.New(c.Reference.Start),
		EndTime: timestamppb.New(c.Reference.End), SampleSize: int32(c.SampleSize), NewOperations: c.NewOperations, //nolint:gosec // G115: ≤ 200 runs
		Actions: c.Actions, Accepted: c.Accepted, ReferenceMedianActions: c.ReferenceMedianActions,
		ReferenceMedianAccepted: c.ReferenceMedianAccepted, PostTaskActions: c.PostTaskActions, Basis: string(c.Basis),
		ScopeLimited: c.ScopeLimited,
	}
	for _, d := range c.NewDestinations {
		out.NewDestinations = append(out.NewDestinations, &pantherclawv1.CompareDestination{
			ConnectionId: d.Connection.String(), Name: d.Name, DestinationClass: d.Class, Actions: d.Actions,
		})
	}
	return out, nil
}

// InspectRun implements InvestigationServiceHandler (rows26 D20; HR-401).
func (h *Handler) InspectRun(ctx context.Context, req *pantherclawv1.InspectRunRequest) (*pantherclawv1.InspectRunResponse, error) {
	id, err := idOf(req.GetRunId())
	if err != nil {
		return nil, err
	}
	o := investigations.InspectOptions{PageSize: int(req.GetTimelinePageSize()), PageToken: req.GetTimelinePageToken()}
	for _, s := range req.GetInclude() {
		o.Sections = append(o.Sections, investigations.Section(s))
	}
	x, err := h.svc.InspectRun(ctx, id, o)
	if err != nil {
		return nil, err
	}
	r := x.Run
	out := &pantherclawv1.InspectRunResponse{
		Run: &pantherclawv1.RunSummary{
			RunId: r.Run.String(), AgentId: r.Agent.String(), TaskRef: r.TaskRef, Launcher: party(r.Launcher),
			Principal: party(r.Principal), GrantId: str(r.Grant), State: r.State, StartTime: timestamppb.New(r.Start),
			EndTime: ts(r.End), EndReason: r.EndReason, ParentRunId: str(r.Parent), Depth: int32(r.Depth), //nolint:gosec // G115: depth ≤ 8
		},
		NextPageToken: x.NextPageToken, TimelineTruncated: x.TimelineTruncated, ScopeLimited: x.ScopeLimited,
	}
	for _, s := range x.Omitted {
		out.OmittedSections = append(out.OmittedSections, pantherclawv1.InspectSection(s)) //nolint:gosec // G115: a section number
	}
	if l := x.Lineage; l != nil {
		lin := &pantherclawv1.RunLineage{
			ChildrenTruncated: l.ChildrenTruncated, UpstreamExecution: execution(l.Upstream), DownstreamTruncated: l.DownstreamTruncated,
		}
		lin.Parents = delegations(l.Parents)
		for _, c := range l.Children {
			lin.Children = append(lin.Children, lane(c))
		}
		for i := range l.Downstream {
			lin.DownstreamExecutions = append(lin.DownstreamExecutions, execution(&l.Downstream[i]))
		}
		out.Lineage = lin
	}
	if x.HasTimeline {
		tl := &pantherclawv1.RunTimeline{}
		for _, e := range x.Events {
			tl.Events = append(tl.Events, event(e))
		}
		for _, p := range x.Phases {
			tl.Phases = append(tl.Phases, phase(p))
		}
		out.Timeline = tl
	}
	for _, b := range x.Budget {
		out.Budget = append(out.Budget, &pantherclawv1.RunBudgetLine{
			AccountId: b.Account.String(), Rule: b.Rule, Currency: b.Currency, Held: b.Held, Committed: b.Committed,
			Released: b.Released, Count: b.Count, Remaining: b.Remaining,
		})
	}
	for _, a := range x.Approvals {
		out.Approvals = append(out.Approvals, approval(a))
	}
	for _, c := range x.Coverage {
		out.Coverage = append(out.Coverage, &pantherclawv1.RunRouteCoverage{
			ConnectionId: c.Connection.String(), Operation: c.Operation, SnapshotId: c.Snapshot.String(), State: c.State,
			Reasons: c.Reasons, ComputedAt: timestamppb.New(c.Computed), StaleAtDecision: c.StaleAtDecision,
		})
	}
	for _, g := range x.Gaps {
		rg := &pantherclawv1.RunGap{
			Kind: g.Kind, Time: timestamppb.New(g.At), GatewayId: str(g.Gateway), ConnectionId: str(g.Connection), Operation: g.Operation,
		}
		if !g.Transaction.IsZero() {
			rg.TransactionId = g.Transaction.String()
		}
		out.Gaps = append(out.Gaps, rg)
	}
	return out, nil
}

func execution(e *investigations.ExecutionLink) *pantherclawv1.RunExecutionLink {
	if e == nil {
		return nil
	}
	return &pantherclawv1.RunExecutionLink{
		ExecutionId: e.Execution.String(), AutomationId: e.Automation.String(), Mode: e.Mode, State: e.State,
		TriggerKind: e.TriggerKind, CreateTime: timestamppb.New(e.Created), EndTime: ts(e.Ended),
	}
}

func delegations(ds []investigations.Delegation) []*pantherclawv1.InvestigationDelegation {
	var out []*pantherclawv1.InvestigationDelegation
	for _, d := range ds {
		out = append(out, &pantherclawv1.InvestigationDelegation{
			RunId: d.Run.String(), AgentId: d.Agent.String(), Launcher: party(d.Launcher), Principal: party(d.Principal),
			GrantId: str(d.Grant), Depth: int32(d.Depth), //nolint:gosec // G115: depth ≤ 8
		})
	}
	return out
}

func lane(l investigations.Lane) *pantherclawv1.TimelineLane {
	out := &pantherclawv1.TimelineLane{
		RunId: l.Run.String(), AgentId: l.Agent.String(), State: l.State, CreateTime: timestamppb.New(l.Created), EndTime: ts(l.Ended),
		EventsTruncated: l.EventsTruncated,
	}
	for _, e := range l.Events {
		out.Events = append(out.Events, event(e))
	}
	for _, g := range l.Gaps {
		out.Gaps = append(out.Gaps, gap(g))
	}
	return out
}

func gap(g investigations.Gap) *pantherclawv1.TimelineGap {
	return &pantherclawv1.TimelineGap{Kind: g.Kind, TransactionId: g.Transaction.String(), Time: timestamppb.New(g.At)}
}

func event(e investigations.Event) *pantherclawv1.TimelineEvent {
	return &pantherclawv1.TimelineEvent{
		Time: timestamppb.New(e.At), Kind: e.Kind, TransactionId: str(e.Transaction), ApprovalId: str(e.Approval),
		GrantId: str(e.Grant), RunId: str(e.Run), Operation: e.Operation, ConnectionId: str(e.Connection), Detail: e.Detail,
		ReadClass: e.ReadClass,
	}
}

func phase(p investigations.Phase) *pantherclawv1.TimelinePhase {
	return &pantherclawv1.TimelinePhase{
		StartTime: timestamppb.New(p.Start), EndTime: timestamppb.New(p.End), ConnectionId: str(p.Connection),
		Actions: int32(p.Actions), Operations: p.Operations, Basis: string(p.Basis), //nolint:gosec // G115: ≤ 2000 actions
	}
}

func approval(a investigations.Approval) *pantherclawv1.InvestigationApproval {
	return &pantherclawv1.InvestigationApproval{
		Id: a.ID.String(), TransactionId: str(a.Transaction), Operation: a.Operation, State: a.State, EndReason: a.EndReason,
		CreateTime: timestamppb.New(a.Created), ApproveTime: ts(a.Approved), EndTime: ts(a.Ended),
	}
}
