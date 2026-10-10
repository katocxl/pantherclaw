// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package agentsrpc serves AgentService over Connect. Handlers only
// translate: ids are parsed, requests become use-case calls, results become
// protos. Authentication, the coarse permission check and protovalidate
// have run before a handler is called; the use cases authorize at the
// agent's place in the hierarchy.
package agentsrpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/agents/domain"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// Agents serves AgentService.
type Agents struct {
	pantherclawv1connect.UnimplementedAgentServiceHandler
	inv     *app.Inventory
	restore *approvals.Service
}

// NewAgents returns the AgentService handler.
func NewAgents(inv *app.Inventory) *Agents { return &Agents{inv: inv} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

// parseID parses a required id; every stored id is a UUIDv7.
func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func parseOptID(s string) (ids.UUID, error) {
	if s == "" {
		return ids.UUID{}, nil
	}
	return parseID(s)
}

var stateToProto = map[domain.State]pantherclawv1.AgentState{
	domain.StateDiscovered:         pantherclawv1.AgentState_AGENT_STATE_DISCOVERED,
	domain.StateClaimed:            pantherclawv1.AgentState_AGENT_STATE_CLAIMED,
	domain.StateVerified:           pantherclawv1.AgentState_AGENT_STATE_VERIFIED,
	domain.StateObserved:           pantherclawv1.AgentState_AGENT_STATE_OBSERVED,
	domain.StatePartiallyProtected: pantherclawv1.AgentState_AGENT_STATE_PARTIALLY_PROTECTED,
	domain.StateProtected:          pantherclawv1.AgentState_AGENT_STATE_PROTECTED,
	domain.StateSuspended:          pantherclawv1.AgentState_AGENT_STATE_SUSPENDED,
	domain.StateRetired:            pantherclawv1.AgentState_AGENT_STATE_RETIRED,
}

var contextToProto = map[domain.ExecutionContext]pantherclawv1.ExecutionContext{
	domain.ContextDesktop:    pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_DESKTOP,
	domain.ContextCI:         pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI,
	domain.ContextKubernetes: pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_KUBERNETES,
	domain.ContextService:    pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_SERVICE,
}

var activityToProto = map[domain.ActivityStatus]pantherclawv1.ActivityStatus{
	domain.ActivityNoInstances:       pantherclawv1.ActivityStatus_ACTIVITY_STATUS_NO_INSTANCES,
	domain.ActivityVerifiedNoActions: pantherclawv1.ActivityStatus_ACTIVITY_STATUS_VERIFIED_NO_ACTIONS,
	domain.ActivityActive:            pantherclawv1.ActivityStatus_ACTIVITY_STATUS_ACTIVE,
}

func contextFromProto(c pantherclawv1.ExecutionContext) domain.ExecutionContext {
	for k, v := range contextToProto {
		if v == c {
			return k
		}
	}
	return ""
}

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func idString(u ids.UUID) string {
	if u.IsZero() {
		return ""
	}
	return u.String()
}

func agentProto(a app.Agent) *pantherclawv1.Agent {
	return &pantherclawv1.Agent{
		Id: a.ID.String(), Name: a.Name, Purpose: a.Purpose, TeamId: idString(a.TeamID),
		EnvironmentId: idString(a.EnvironmentID), OwnerUserId: idString(a.OwnerUserID),
		BackupOwnerUserId: idString(a.BackupOwnerUserID), ExecutionContext: contextToProto[a.Context],
		State: stateToProto[a.State], SuspendedFrom: stateToProto[a.SuspendedFrom], CreatedBy: a.CreatedBy,
		CreateTime: ts(a.CreatedAt), UpdateTime: ts(a.UpdatedAt), ClaimTime: tsp(a.ClaimedAt), RetireTime: tsp(a.RetiredAt),
	}
}

func summaryProto(s app.Summary) *pantherclawv1.AgentSummary {
	out := &pantherclawv1.AgentSummary{
		Agent: agentProto(s.Agent), Activity: activityToProto[s.Activity], NextAction: s.NextAction,
		PendingInstances: int32(s.PendingInstances), AdmittedInstances: int32(s.AdmittedInstances), //nolint:gosec // G115: small counts
		HighestAttestationLevel: int32(s.HighestLevel), LastVerifyTime: tsp(s.LastVerifiedAt), //nolint:gosec // G115: 0..2
		ActiveRuns: int32(s.ActiveRuns), OpenWaitlistEntries: int32(s.OpenEntries), //nolint:gosec // G115: small counts
		InstancesNeedingReview: int32(s.NeedingReview), //nolint:gosec // G115: small counts
	}
	if d := s.Discovery; d != nil {
		out.Discovery = &pantherclawv1.Discovery{
			Id: d.ID.String(), Source: d.Source, KeyThumbprint: d.KeyThumbprint, State: d.State, SeenCount: d.SeenCount,
			FirstSeenTime: ts(d.FirstSeenAt), LastSeenTime: ts(d.LastSeenAt), UntrustedObserved: d.Observed,
		}
	}
	return out
}

func details(name, purpose, team, env, owner, backup string, c pantherclawv1.ExecutionContext) (domain.Details, error) {
	var d domain.Details
	var err error
	d.Name, d.Purpose, d.Context = name, purpose, contextFromProto(c)
	for dst, src := range map[*ids.UUID]string{&d.TeamID: team, &d.EnvironmentID: env, &d.OwnerUserID: owner} {
		if *dst, err = parseID(src); err != nil {
			return d, err
		}
	}
	d.BackupOwnerUserID, err = parseOptID(backup)
	return d, err
}

// CreateAgent implements AgentServiceHandler.
func (s *Agents) CreateAgent(ctx context.Context, req *pantherclawv1.CreateAgentRequest) (*pantherclawv1.CreateAgentResponse, error) {
	d, err := details(req.GetName(), req.GetPurpose(), req.GetTeamId(), req.GetEnvironmentId(), req.GetOwnerUserId(),
		req.GetBackupOwnerUserId(), req.GetExecutionContext())
	if err != nil {
		return nil, err
	}
	a, err := s.inv.Create(ctx, d)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateAgentResponse{Agent: agentProto(a)}, nil
}

// GetAgent implements AgentServiceHandler.
func (s *Agents) GetAgent(ctx context.Context, req *pantherclawv1.GetAgentRequest) (*pantherclawv1.GetAgentResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	sum, err := s.inv.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetAgentResponse{Summary: summaryProto(sum)}, nil
}

// ListAgents implements AgentServiceHandler.
func (s *Agents) ListAgents(ctx context.Context, req *pantherclawv1.ListAgentsRequest) (*pantherclawv1.ListAgentsResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	team, err := parseOptID(req.GetTeamId())
	if err != nil {
		return nil, err
	}
	var states []domain.State
	for _, st := range req.GetStates() {
		for k, v := range stateToProto {
			if v == st {
				states = append(states, k)
			}
		}
	}
	p, none, err := s.inv.List(ctx, pr, states, team)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAgentsResponse{NextPageToken: p.Next, OrgHasNoAgents: none}
	for _, a := range p.Items {
		out.Agents = append(out.Agents, agentProto(a))
	}
	return out, nil
}

// UpdateAgent implements AgentServiceHandler.
func (s *Agents) UpdateAgent(ctx context.Context, req *pantherclawv1.UpdateAgentRequest) (*pantherclawv1.UpdateAgentResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := s.inv.Update(ctx, id, req.Name, req.Purpose)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateAgentResponse{Agent: agentProto(a)}, nil
}

// TransferOwnership implements AgentServiceHandler.
func (s *Agents) TransferOwnership(ctx context.Context, req *pantherclawv1.TransferOwnershipRequest) (*pantherclawv1.TransferOwnershipResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	owner, err := parseID(req.GetOwnerUserId())
	if err != nil {
		return nil, err
	}
	backup, err := parseOptID(req.GetBackupOwnerUserId())
	if err != nil {
		return nil, err
	}
	a, err := s.inv.TransferOwnership(ctx, id, owner, backup, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.TransferOwnershipResponse{Agent: agentProto(a)}, nil
}

// ClaimAgent implements AgentServiceHandler.
func (s *Agents) ClaimAgent(ctx context.Context, req *pantherclawv1.ClaimAgentRequest) (*pantherclawv1.ClaimAgentResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	var d *domain.Details
	var into ids.UUID
	if n := req.GetAsNewAgent(); n != nil {
		det, err := details(n.GetName(), n.GetPurpose(), n.GetTeamId(), n.GetEnvironmentId(), n.GetOwnerUserId(),
			n.GetBackupOwnerUserId(), n.GetExecutionContext())
		if err != nil {
			return nil, err
		}
		d = &det
	} else if into, err = parseID(req.GetMergeIntoAgentId()); err != nil {
		return nil, err
	}
	a, err := s.inv.Claim(ctx, id, d, into, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ClaimAgentResponse{Agent: agentProto(a)}, nil
}

// SuspendAgent implements AgentServiceHandler.
func (s *Agents) SuspendAgent(ctx context.Context, req *pantherclawv1.SuspendAgentRequest) (*pantherclawv1.SuspendAgentResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := s.inv.Suspend(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SuspendAgentResponse{Agent: agentProto(a)}, nil
}

// RetireAgent implements AgentServiceHandler.
func (s *Agents) RetireAgent(ctx context.Context, req *pantherclawv1.RetireAgentRequest) (*pantherclawv1.RetireAgentResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := s.inv.Retire(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetireAgentResponse{Agent: agentProto(a)}, nil
}

// ListAgentChanges implements AgentServiceHandler.
func (s *Agents) ListAgentChanges(ctx context.Context, req *pantherclawv1.ListAgentChangesRequest) (*pantherclawv1.ListAgentChangesResponse, error) {
	id, err := parseID(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := s.inv.ListChanges(ctx, id, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAgentChangesResponse{NextPageToken: p.Next}
	for _, c := range p.Items {
		out.Changes = append(out.Changes, &pantherclawv1.AgentChange{
			Id: c.ID.String(), AgentId: c.AgentID.String(), Kind: c.Kind, Actor: c.Actor, Reason: c.Reason,
			Details: c.Details, CreateTime: ts(c.CreatedAt),
		})
	}
	return out, nil
}

// SubmitScanFindings implements AgentServiceHandler.
func (s *Agents) SubmitScanFindings(ctx context.Context, req *pantherclawv1.SubmitScanFindingsRequest) (*pantherclawv1.SubmitScanFindingsResponse, error) {
	findings := make([]app.ScanFinding, 0, len(req.GetFindings()))
	for _, f := range req.GetFindings() {
		k, err := hex.DecodeString(f.GetKey())
		if err != nil || len(k) != 32 {
			return nil, pcerr.New(pcerr.InvalidArgument, "SCAN_KEY", "a finding key is 64 hex digits")
		}
		findings = append(findings, app.ScanFinding{Kind: f.GetKind(), Key: [32]byte(k), Attributes: f.GetAttributes()})
	}
	r, err := s.inv.SubmitScan(ctx, req.GetHost(), findings)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SubmitScanFindingsResponse{
		Created: int32(r.Created), Counted: int32(r.Counted), Dropped: int32(r.Dropped), //nolint:gosec // G115: at most 200
	}, nil
}
