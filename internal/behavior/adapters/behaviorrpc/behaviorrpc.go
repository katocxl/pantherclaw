// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package behaviorrpc serves BehaviorService over Connect (G0 M27 D501,
// D502). Handlers only translate: authentication, the coarse permission
// check and protovalidate have run before a handler is called, and the use
// cases check scope and the edition. Every answer carries the labels.
package behaviorrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	bapp "github.com/katocxl/pantherclaw/internal/behavior/app"
	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var errBadID = pcerr.New(pcerr.InvalidArgument, "BEHAVIOR_ID_INVALID", "an id is not a UUID")

// Handler serves BehaviorService.
type Handler struct {
	pantherclawv1connect.UnimplementedBehaviorServiceHandler
	svc *bapp.Service
}

// New returns the BehaviorService handler.
func New(svc *bapp.Service) *Handler { return &Handler{svc: svc} }

var states = map[bdomain.State]pb.BehaviorProfileState{
	bdomain.StateCollected:    pb.BehaviorProfileState_BEHAVIOR_PROFILE_STATE_COLLECTED,
	bdomain.StateInsufficient: pb.BehaviorProfileState_BEHAVIOR_PROFILE_STATE_INSUFFICIENT_HISTORY,
	bdomain.StateNotCollected: pb.BehaviorProfileState_BEHAVIOR_PROFILE_STATE_NOT_COLLECTED,
}

var kinds = map[bdomain.Kind]pb.BehaviorDeviationKind{
	bdomain.KindNewTool:        pb.BehaviorDeviationKind_BEHAVIOR_DEVIATION_KIND_NEW_TOOL,
	bdomain.KindNewDestination: pb.BehaviorDeviationKind_BEHAVIOR_DEVIATION_KIND_NEW_DESTINATION,
	bdomain.KindUnusualHour:    pb.BehaviorDeviationKind_BEHAVIOR_DEVIATION_KIND_UNUSUAL_HOUR,
	bdomain.KindNewSequence:    pb.BehaviorDeviationKind_BEHAVIOR_DEVIATION_KIND_NEW_SEQUENCE,
	bdomain.KindVolumeSpike:    pb.BehaviorDeviationKind_BEHAVIOR_DEVIATION_KIND_VOLUME_SPIKE,
	bdomain.KindSpendSpike:     pb.BehaviorDeviationKind_BEHAVIOR_DEVIATION_KIND_SPEND_SPIKE,
}

func originOf(o pb.BehaviorOrigin) bdomain.Origin {
	if o == pb.BehaviorOrigin_BEHAVIOR_ORIGIN_SIMULATED {
		return bdomain.OriginSimulated
	}
	return bdomain.OriginReal
}

func originPB(o bdomain.Origin) pb.BehaviorOrigin {
	if o == bdomain.OriginSimulated {
		return pb.BehaviorOrigin_BEHAVIOR_ORIGIN_SIMULATED
	}
	return pb.BehaviorOrigin_BEHAVIOR_ORIGIN_REAL
}

func stamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// GetAgentProfile implements BehaviorService.
func (h *Handler) GetAgentProfile(ctx context.Context, r *pb.GetAgentProfileRequest) (*pb.GetAgentProfileResponse, error) {
	agent, err := ids.ParseUUID(r.GetAgentId())
	if err != nil {
		return nil, errBadID
	}
	p, err := h.svc.Profile(ctx, agent, originOf(r.GetOrigin()))
	if err != nil {
		return nil, err
	}
	return &pb.GetAgentProfileResponse{Profile: profilePB(p)}, nil
}

// GetBehaviorContext implements BehaviorService.
func (h *Handler) GetBehaviorContext(ctx context.Context, r *pb.GetBehaviorContextRequest) (*pb.GetBehaviorContextResponse, error) {
	approval, err := ids.ParseUUID(r.GetApprovalId())
	if err != nil {
		return nil, errBadID
	}
	c, err := h.svc.Context(ctx, approval)
	if err != nil {
		return nil, err
	}
	out := &pb.GetBehaviorContextResponse{
		AgentId: c.Agent.String(), Origin: originPB(c.Profile.Origin), State: states[c.Profile.State],
		ActionCount: c.Profile.Actions, ActiveDays: int32(c.Profile.ActiveDays), //nolint:gosec // at most 31 days
		Basis: bdomain.Basis, DefinitionStatus: bdomain.DefinitionStatus, Label: bdomain.Label, AsOfTime: stamp(c.Profile.AsOf),
	}
	for _, d := range c.Lines {
		out.Lines = append(out.Lines, &pb.BehaviorContextLine{Kind: kinds[d.Kind], Text: d.Text})
	}
	return out, nil
}

func profilePB(p bdomain.BehaviorProfile) *pb.BehaviorProfile {
	out := &pb.BehaviorProfile{
		AgentId: p.Agent.String(), Origin: originPB(p.Origin), State: states[p.State],
		WindowStartTime: stamp(p.Start), WindowEndTime: stamp(p.End), ActionCount: p.Actions,
		ActiveDays: int32(p.ActiveDays), //nolint:gosec // at most 31 days
		Hours:      p.Body.Hours, Truncated: p.Truncated, Basis: bdomain.Basis, DefinitionStatus: bdomain.DefinitionStatus,
		Label: bdomain.Label, AsOfTime: stamp(p.AsOf),
	}
	if p.State == bdomain.StateNotCollected {
		return out
	}
	v := p.Body.Volumes
	out.Volumes = &pb.BehaviorVolumes{
		MedianDaily: v.MedianDaily, P90Daily: v.P90Daily, MaxDaily: v.MaxDaily, MaxHourly: v.MaxHourly,
	}
	for _, t := range p.Body.Tools {
		out.Tools = append(out.Tools, &pb.BehaviorTool{Operation: t.Operation, Count: t.Count})
	}
	for _, d := range p.Body.Destinations {
		out.Destinations = append(out.Destinations, &pb.BehaviorDestination{
			ConnectionId: d.Connection, DestinationClass: d.Class, Count: d.Count,
		})
	}
	for _, s := range p.Body.Sequences {
		out.Sequences = append(out.Sequences, &pb.BehaviorSequence{FromOperation: s.From, ToOperation: s.To, Count: s.Count})
	}
	for _, s := range p.Body.Spend {
		out.Spend = append(out.Spend, &pb.BehaviorSpend{
			Currency: s.Currency, MedianDaily: s.MedianDaily, MaxDaily: s.MaxDaily,
			Days: int32(s.Days), //nolint:gosec // at most 31 days
		})
	}
	return out
}
