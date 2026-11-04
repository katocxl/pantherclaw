// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package runsrpc serves RunService over Connect (G0 M3). Child runs are
// started by workloads through WorkloadService.
package runsrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/runs/app"
)

// Runs serves RunService.
type Runs struct {
	pantherclawv1connect.UnimplementedRunServiceHandler
	svc *app.Service
}

// NewRuns returns the RunService handler.
func NewRuns(svc *app.Service) *Runs { return &Runs{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// ParseID accepts a UUIDv7, the only kind of id PantherClaw mints.
func ParseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

var (
	stateToProto = map[string]pantherclawv1.RunState{
		"ACTIVE":    pantherclawv1.RunState_RUN_STATE_ACTIVE,
		"ENDED":     pantherclawv1.RunState_RUN_STATE_ENDED,
		"CANCELLED": pantherclawv1.RunState_RUN_STATE_CANCELLED, //nolint:misspell // stored value
		"EXPIRED":   pantherclawv1.RunState_RUN_STATE_EXPIRED,
		"REVOKED":   pantherclawv1.RunState_RUN_STATE_REVOKED,
	}
	subjectTypes = map[pantherclawv1.SubjectTokenType]string{
		pantherclawv1.SubjectTokenType_SUBJECT_TOKEN_TYPE_ID_TOKEN:     app.SubjectIDToken,
		pantherclawv1.SubjectTokenType_SUBJECT_TOKEN_TYPE_ACCESS_TOKEN: app.SubjectAccessToken,
	}
	sourceToProto = map[string]pantherclawv1.PrincipalSource{
		app.SourceLauncher:     pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_LAUNCHER,
		app.SourceSubjectToken: pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_SUBJECT_TOKEN,
		app.SourceParentRun:    pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_PARENT_RUN,
		app.SourceIDJAG:        pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_ID_JAG,
		app.SourceAutomation:   pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_AUTOMATION,
	}
)

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func actor(a app.Actor) *pantherclawv1.Actor { return &pantherclawv1.Actor{Kind: a.Kind, Id: a.ID} }

func optID(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// RunProto renders a run.
func RunProto(r app.Run) *pantherclawv1.Run {
	out := &pantherclawv1.Run{
		Id: r.ID.String(), AgentId: r.AgentID.String(), InstanceId: optID(r.InstanceID), EnvironmentId: r.EnvironmentID.String(),
		Launcher: actor(r.Launcher), Principal: actor(r.Principal), PrincipalSource: sourceToProto[r.PrincipalSource],
		SubjectIssuer: r.SubjectIssuer, SubjectSubject: r.SubjectSubject, ParentRunId: optID(r.ParentRunID),
		Depth: int32(r.Depth), TaskRef: r.TaskRef, State: stateToProto[r.State], EndReason: r.EndReason, //nolint:gosec // G115: at most 8
		CreateTime: ts(r.CreatedAt), ExpireTime: ts(r.ExpiresAt), GrantId: optID(r.GrantID),
		ScopeOperations: r.ScopeOperations,
	}
	for _, a := range r.ActorChain {
		out.ActorChain = append(out.ActorChain, actor(a))
	}
	if r.EndedAt != nil {
		out.EndTime = timestamppb.New(*r.EndedAt)
	}
	return out
}

// StartRun implements RunServiceHandler.
func (s *Runs) StartRun(ctx context.Context, req *pantherclawv1.StartRunRequest) (*pantherclawv1.StartRunResponse, error) {
	agent, err := ParseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	in := app.StartInput{
		AgentID: agent, TaskRef: req.GetTaskRef(), TTL: time.Duration(req.GetTtlMinutes()) * time.Minute,
		SubjectToken: req.GetSubjectToken(), SubjectTokenType: subjectTypes[req.GetSubjectTokenType()],
	}
	if req.InstanceId != nil {
		id, err := ParseID(req.GetInstanceId())
		if err != nil {
			return nil, err
		}
		in.InstanceID = &id
	}
	if req.GrantId != nil {
		id, err := ParseID(req.GetGrantId())
		if err != nil {
			return nil, err
		}
		in.GrantID = &id
	}
	r, err := s.svc.StartRun(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartRunResponse{Run: RunProto(r)}, nil
}

// GetRun implements RunServiceHandler.
func (s *Runs) GetRun(ctx context.Context, req *pantherclawv1.GetRunRequest) (*pantherclawv1.GetRunResponse, error) {
	id, err := ParseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.GetRun(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetRunResponse{Run: RunProto(r)}, nil
}

// ListRuns implements RunServiceHandler.
func (s *Runs) ListRuns(ctx context.Context, req *pantherclawv1.ListRunsRequest) (*pantherclawv1.ListRunsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	var agent *ids.UUID
	if req.AgentId != nil {
		id, err := ParseID(req.GetAgentId())
		if err != nil {
			return nil, err
		}
		agent = &id
	}
	var states []string
	for _, st := range req.GetStates() {
		for k, v := range stateToProto {
			if v == st {
				states = append(states, k)
			}
		}
	}
	p, err := s.svc.ListRuns(ctx, pr, agent, states)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListRunsResponse{NextPageToken: p.Next}
	for _, r := range p.Items {
		out.Runs = append(out.Runs, RunProto(r))
	}
	return out, nil
}

// EndRun implements RunServiceHandler.
func (s *Runs) EndRun(ctx context.Context, req *pantherclawv1.EndRunRequest) (*pantherclawv1.EndRunResponse, error) {
	id, err := ParseID(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := s.svc.EndRun(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.EndRunResponse{Run: RunProto(r)}, nil
}
