// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package queuerpc serves PostureQueueService over Connect (G0 M24 D200).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases check
// scope and the edition.
package queuerpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/postureview/app"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
)

var errBadID = pcerr.New(pcerr.InvalidArgument, "POSTURE_FILTER_ID_INVALID", "a filter id is not a UUID")

// Handler serves PostureQueueService.
type Handler struct {
	pantherclawv1connect.UnimplementedPostureQueueServiceHandler
	svc *app.Service
}

// New returns the PostureQueueService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var bases = map[domain.SeverityBasis]pb.PostureSeverityBasis{
	domain.BasisStated: pb.PostureSeverityBasis_POSTURE_SEVERITY_BASIS_STATED,
	domain.BasisByKind: pb.PostureSeverityBasis_POSTURE_SEVERITY_BASIS_BY_KIND,
}

var sourceStates = map[app.SourceState]pb.PostureSourceState{
	app.SourceComplete:     pb.PostureSourceState_POSTURE_SOURCE_STATE_COMPLETE,
	app.SourceTruncated:    pb.PostureSourceState_POSTURE_SOURCE_STATE_TRUNCATED,
	app.SourceRestricted:   pb.PostureSourceState_POSTURE_SOURCE_STATE_RESTRICTED,
	app.SourceNotInEdition: pb.PostureSourceState_POSTURE_SOURCE_STATE_NOT_IN_EDITION,
}

var dayStates = map[app.DayState]pb.PostureDayState{
	app.DayCollected:    pb.PostureDayState_POSTURE_DAY_STATE_COLLECTED,
	app.DayNotCollected: pb.PostureDayState_POSTURE_DAY_STATE_NOT_COLLECTED,
}

func idOf(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// parseID reads an optional id; empty means no filter.
func parseID(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // no filter
	}
	id, err := ids.ParseUUID(s)
	if err != nil {
		return nil, errBadID
	}
	return &id, nil
}

func finding(f domain.RankedFinding) *pb.RankedFinding {
	out := &pb.RankedFinding{
		Source: string(f.Source), SourceId: f.SourceID, Kind: f.Kind, RootCause: f.RootCause, AgentId: idOf(f.AgentID),
		AgentLabel: f.AgentLabel, ConnectionId: idOf(f.ConnectionID), TeamId: idOf(f.TeamID), Title: f.Title,
		Severity: string(f.Severity), SeverityBasis: bases[f.SeverityBasis], State: f.State,
		Fix:   &pb.PostureFix{Kind: string(f.Fix.Kind), TargetId: f.Fix.TargetID, Label: f.Fix.Label, RequiresBusiness: f.Fix.RequiresBusiness},
		Owasp: f.OWASP, RankReasons: f.RankReasons,
	}
	if !f.Since.IsZero() {
		out.Since = timestamppb.New(f.Since)
	}
	return out
}

// ListRankedFindings implements PostureQueueService.
func (h *Handler) ListRankedFindings(ctx context.Context, req *pb.ListRankedFindingsRequest) (*pb.ListRankedFindingsResponse, error) {
	team, err := parseID(req.GetTeamId())
	if err != nil {
		return nil, err
	}
	agent, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	conn, err := parseID(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	l, err := h.svc.List(ctx, domain.Filter{
		Source: domain.Source(req.GetSource()), Kind: req.GetKind(), Severity: domain.Severity(req.GetSeverity()),
		Team: team, Agent: agent, Connection: conn,
	}, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListRankedFindingsResponse{
		NextPageToken: l.Next, Restricted: l.Restricted, Total: int32(l.Total), AsOf: timestamppb.New(l.AsOf), //nolint:gosec // G115: bounded by the sources' caps
	}
	for _, f := range l.Findings {
		out.Findings = append(out.Findings, finding(f))
	}
	for _, s := range l.Sources {
		out.Sources = append(out.Sources, &pb.PostureSourceStatus{
			Source: string(s.Source), State: sourceStates[s.State], Findings: int32(s.Findings), //nolint:gosec // G115: bounded by the sources' caps
		})
	}
	return out, nil
}

// GetPostureTrends implements PostureQueueService.
func (h *Handler) GetPostureTrends(ctx context.Context, req *pb.GetPostureTrendsRequest) (*pb.GetPostureTrendsResponse, error) {
	team, err := parseID(req.GetTeamId())
	if err != nil {
		return nil, err
	}
	t, err := h.svc.Trends(ctx, req.GetDays(), req.GetKind(), team)
	if err != nil {
		return nil, err
	}
	out := &pb.GetPostureTrendsResponse{Restricted: t.Restricted, AsOf: timestamppb.New(t.AsOf)}
	for _, d := range t.Days {
		day := &pb.PostureTrendDay{Day: d.Day, State: dayStates[d.State], TruncatedSources: d.TruncatedSources}
		for _, c := range d.Counts {
			day.Counts = append(day.Counts, &pb.PostureTrendCount{
				Kind: c.Kind, Severity: c.Severity, TeamId: idOf(c.Team), OpenCount: c.Open, ClosedCount: c.Closed,
			})
		}
		out.Days = append(out.Days, day)
	}
	return out, nil
}
