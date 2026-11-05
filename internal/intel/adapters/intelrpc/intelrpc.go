// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package intelrpc serves IntelService over Connect (G0 M38 D1103..D1105).
package intelrpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/intel/app"
	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves IntelService.
type Handler struct {
	pantherclawv1connect.UnimplementedIntelServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

var modeOf = map[domain.Mode]pb.IntelConsumeMode{
	domain.ModeOff:       pb.IntelConsumeMode_INTEL_CONSUME_MODE_OFF,
	domain.ModeHold:      pb.IntelConsumeMode_INTEL_CONSUME_MODE_HOLD,
	domain.ModeAlertOnly: pb.IntelConsumeMode_INTEL_CONSUME_MODE_ALERT_ONLY,
}

func modeFrom(m pb.IntelConsumeMode) domain.Mode {
	for k, v := range modeOf {
		if v == m {
			return k
		}
	}
	return ""
}

var kindOf = map[domain.Kind]pb.IntelIndicatorKind{
	domain.KindMCPServer:       pb.IntelIndicatorKind_INTEL_INDICATOR_KIND_MCP_SERVER,
	domain.KindToolDescription: pb.IntelIndicatorKind_INTEL_INDICATOR_KIND_TOOL_DESCRIPTION,
	domain.KindInjectionText:   pb.IntelIndicatorKind_INTEL_INDICATOR_KIND_INJECTION_TEXT,
}

var sourceOf = map[pb.IntelContributionSource]app.Source{
	pb.IntelContributionSource_INTEL_CONTRIBUTION_SOURCE_QUARANTINED_SERVER:  app.SourceQuarantinedServer,
	pb.IntelContributionSource_INTEL_CONTRIBUTION_SOURCE_QUARANTINED_PACKAGE: app.SourceQuarantinedPackage,
	pb.IntelContributionSource_INTEL_CONTRIBUTION_SOURCE_QUARANTINED_TOOL:    app.SourceQuarantinedTool,
	pb.IntelContributionSource_INTEL_CONTRIBUTION_SOURCE_FLAGGED_DESCRIPTION: app.SourceFlaggedDescription,
}

func settings(s app.Settings) *pb.IntelSettings {
	out := &pb.IntelSettings{Consume: modeOf[s.Consume], Share: s.Share, UpdatedBy: s.UpdatedBy}
	if !s.UpdatedAt.IsZero() {
		out.UpdateTime = timestamppb.New(s.UpdatedAt)
	}
	return out
}

func contribution(c app.Contribution) *pb.IntelContribution {
	return &pb.IntelContribution{
		Id: c.ID.String(), Kind: kindOf[c.Kind], Sha256: c.SHA256, Shingles: c.Shingles, Severity: string(c.Severity),
		Techniques: c.Techniques, CreatedDay: c.CreatedDay, State: c.State,
	}
}

// GetIntelSettings implements IntelServiceHandler.
func (h *Handler) GetIntelSettings(ctx context.Context, _ *pb.GetIntelSettingsRequest) (*pb.GetIntelSettingsResponse, error) {
	o, err := h.s.Get(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.GetIntelSettingsResponse{Settings: settings(o.Settings), ConsumeAvailable: o.ConsumeAvailable}
	if o.Feed != nil {
		out.Feed = &pb.IntelFeed{
			Version: o.Feed.Version, Kid: o.Feed.KID, IssueTime: timestamppb.New(o.Feed.Issued),
			ExpireTime: timestamppb.New(o.Feed.Expires), Indicators: o.Feed.Indicators,
		}
	}
	return out, nil
}

// SetIntelSettings implements IntelServiceHandler.
func (h *Handler) SetIntelSettings(ctx context.Context, req *pb.SetIntelSettingsRequest) (*pb.SetIntelSettingsResponse, error) {
	s, err := h.s.Set(ctx, modeFrom(req.GetConsume()), req.GetShare())
	if err != nil {
		return nil, err
	}
	return &pb.SetIntelSettingsResponse{Settings: settings(s)}, nil
}

// ListIntelMatches implements IntelServiceHandler.
func (h *Handler) ListIntelMatches(ctx context.Context, req *pb.ListIntelMatchesRequest) (*pb.ListIntelMatchesResponse, error) {
	rows, next, err := h.s.ListMatches(ctx, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListIntelMatchesResponse{NextPageToken: next}
	for _, r := range rows {
		m := &pb.IntelMatch{
			Id: r.ID.String(), IndicatorId: r.IndicatorID, Kind: kindOf[domain.Kind(r.Kind)], ObjectType: r.ObjectType,
			ObjectRef: r.ObjectRef, Mode: modeOf[domain.Mode(r.Mode)], MatchTime: timestamppb.New(r.At),
		}
		if r.ConnectionID != nil {
			m.ConnectionId = r.ConnectionID.String()
		}
		if r.Tool != nil {
			m.Tool = *r.Tool
		}
		out.Matches = append(out.Matches, m)
	}
	return out, nil
}

// ContributeIndicator implements IntelServiceHandler.
func (h *Handler) ContributeIndicator(ctx context.Context, req *pb.ContributeIndicatorRequest) (*pb.ContributeIndicatorResponse, error) {
	id, err := ids.ParseUUID(req.GetSourceId())
	if err != nil {
		return nil, app.ErrSourceMissing
	}
	src, ok := sourceOf[req.GetSource()]
	if !ok {
		return nil, app.ErrSource
	}
	c, err := h.s.Contribute(ctx, src, id, domain.Severity(req.GetSeverity()), req.GetTechniques())
	if err != nil {
		return nil, err
	}
	return &pb.ContributeIndicatorResponse{Contribution: contribution(c)}, nil
}

// ListIntelContributions implements IntelServiceHandler.
func (h *Handler) ListIntelContributions(ctx context.Context, _ *pb.ListIntelContributionsRequest) (*pb.ListIntelContributionsResponse, error) {
	rows, err := h.s.ListContributions(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListIntelContributionsResponse{}
	for _, c := range rows {
		out.Contributions = append(out.Contributions, contribution(c))
	}
	return out, nil
}

// ExportIntelSTIX implements IntelServiceHandler.
func (h *Handler) ExportIntelSTIX(ctx context.Context, _ *pb.ExportIntelSTIXRequest) (*pb.ExportIntelSTIXResponse, error) {
	b, err := h.s.ExportSTIX(ctx)
	if err != nil {
		return nil, err
	}
	return &pb.ExportIntelSTIXResponse{Bundle: b}, nil
}
