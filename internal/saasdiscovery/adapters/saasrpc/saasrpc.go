// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package saasrpc serves SaasDiscoveryService over Connect (G0 M26 D407).
package saasrpc

import (
	"context"
	"encoding/hex"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	agentsdomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/app"
)

// Handler serves SaasDiscoveryService.
type Handler struct {
	pantherclawv1connect.UnimplementedSaasDiscoveryServiceHandler
	s *app.Service
}

// New returns the handler.
func New(s *app.Service) *Handler { return &Handler{s: s} }

var (
	errInvalidID  = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")
	errInvalidKey = pcerr.New(pcerr.InvalidArgument, "SAAS_FINDING", "a finding's key is 64 hex characters")
)

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil || id.IsZero() {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
}

func optID(s string) (ids.UUID, error) {
	if s == "" {
		return ids.UUID{}, nil
	}
	return idOf(s)
}

func idString(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func tsp(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

var stateOf = map[string]pantherclawv1.SaasScanState{
	"PENDING": pantherclawv1.SaasScanState_SAAS_SCAN_STATE_PENDING,
	"RUNNING": pantherclawv1.SaasScanState_SAAS_SCAN_STATE_RUNNING,
	"DONE":    pantherclawv1.SaasScanState_SAAS_SCAN_STATE_DONE,
	"FAILED":  pantherclawv1.SaasScanState_SAAS_SCAN_STATE_FAILED,
}

func scanProto(s app.Scan) *pantherclawv1.SaasScan {
	return &pantherclawv1.SaasScan{
		Id: s.ID.String(), Source: s.Source, Origin: s.Origin, Tenant: s.Tenant, ConnectionId: idString(s.ConnectionID),
		State: stateOf[s.State], Counts: s.Counts, Scanned: s.Scanned, NotScanned: s.NotScanned, StartedBy: s.StartedBy,
		CreateTime: timestamppb.New(s.CreatedAt), FinishTime: tsp(s.FinishedAt),
	}
}

func agentProto(a app.Agent) *pantherclawv1.SaasAgent {
	return &pantherclawv1.SaasAgent{
		AgentId: a.ID.String(), Source: a.Source, Coverage: pantherclawv1.CoverageState_COVERAGE_STATE_OBSERVE_ONLY,
		OwnerUserId: idString(a.OwnerUserID), BackupOwnerUserId: idString(a.BackupOwnerUserID), DiscoveryState: a.DiscoveryState,
		Attributes: a.Attributes, SeenCount: a.SeenCount, MissedScans: a.MissedScans,
		FirstSeenTime: timestamppb.New(a.FirstSeenAt), LastSeenTime: timestamppb.New(a.LastSeenAt),
		Status: agentsdomain.ExternalStatus(a.DiscoveryState),
	}
}

// ImportSaasReport implements SaasDiscoveryServiceHandler.
func (h *Handler) ImportSaasReport(ctx context.Context, req *pantherclawv1.ImportSaasReportRequest) (*pantherclawv1.ImportSaasReportResponse, error) {
	findings := make([]agents.ScanFinding, 0, len(req.GetFindings()))
	for _, f := range req.GetFindings() {
		key, err := hex.DecodeString(f.GetKey())
		if err != nil || len(key) != 32 {
			return nil, errInvalidKey
		}
		findings = append(findings, agents.ScanFinding{Kind: f.GetKind(), Key: [32]byte(key), Attributes: f.GetAttributes()})
	}
	scan, res, err := h.s.Import(ctx, agents.SaaSReport{
		Source: req.GetSource(), Tenant: req.GetTenant(), Findings: findings, Scanned: req.GetScanned(), NotScanned: req.GetNotScanned(),
		Counts: req.GetCounts(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ImportSaasReportResponse{
		Scan: scanProto(scan), Created: int32(res.Created), Counted: int32(res.Counted), Dropped: int32(res.Dropped), //nolint:gosec // G115: at most 200
		Reopened: int32(res.Reopened), Missed: int32(res.Missed), DroppedAttributes: int32(res.DroppedAttributes), //nolint:gosec // G115: small counts
	}, nil
}

// StartSaasScan implements SaasDiscoveryServiceHandler.
func (h *Handler) StartSaasScan(ctx context.Context, req *pantherclawv1.StartSaasScanRequest) (*pantherclawv1.StartSaasScanResponse, error) {
	connection, err := idOf(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	scan, err := h.s.Start(ctx, connection, req.GetSource(), req.GetTenant())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartSaasScanResponse{Scan: scanProto(scan)}, nil
}

// GetSaasScan implements SaasDiscoveryServiceHandler.
func (h *Handler) GetSaasScan(ctx context.Context, req *pantherclawv1.GetSaasScanRequest) (*pantherclawv1.GetSaasScanResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	scan, err := h.s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSaasScanResponse{Scan: scanProto(scan)}, nil
}

// ListSaasScans implements SaasDiscoveryServiceHandler.
func (h *Handler) ListSaasScans(ctx context.Context, req *pantherclawv1.ListSaasScansRequest) (*pantherclawv1.ListSaasScansResponse, error) {
	scans, next, err := h.s.List(ctx, req.GetSource(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSaasScansResponse{NextPageToken: next}
	for _, s := range scans {
		out.Scans = append(out.Scans, scanProto(s))
	}
	return out, nil
}

// ListSaasAgents implements SaasDiscoveryServiceHandler.
func (h *Handler) ListSaasAgents(ctx context.Context, req *pantherclawv1.ListSaasAgentsRequest) (*pantherclawv1.ListSaasAgentsResponse, error) {
	list, next, err := h.s.ListAgents(ctx, req.GetSource(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSaasAgentsResponse{NextPageToken: next}
	for _, a := range list {
		out.Agents = append(out.Agents, agentProto(a))
	}
	return out, nil
}

// SetSaasAgentOwner implements SaasDiscoveryServiceHandler.
func (h *Handler) SetSaasAgentOwner(ctx context.Context, req *pantherclawv1.SetSaasAgentOwnerRequest) (*pantherclawv1.SetSaasAgentOwnerResponse, error) {
	id, err := idOf(req.GetAgentId())
	if err != nil {
		return nil, err
	}
	owner, err := idOf(req.GetOwnerUserId())
	if err != nil {
		return nil, err
	}
	backup, err := optID(req.GetBackupOwnerUserId())
	if err != nil {
		return nil, err
	}
	a, err := h.s.SetOwner(ctx, id, owner, backup, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetSaasAgentOwnerResponse{Agent: agentProto(a)}, nil
}

// SetSaaSScanSchedule implements SaasDiscoveryServiceHandler (G0 M34 D997).
func (h *Handler) SetSaaSScanSchedule(ctx context.Context, req *pantherclawv1.SetSaaSScanScheduleRequest) (*pantherclawv1.SetSaaSScanScheduleResponse, error) {
	connection, err := idOf(req.GetConnectionId())
	if err != nil {
		return nil, err
	}
	sch, err := h.s.SetSchedule(ctx, req.GetSource(), connection, req.GetDaily())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SetSaaSScanScheduleResponse{}
	if sch != nil {
		out.Schedule = &pantherclawv1.SaaSScanSchedule{
			Source: sch.Source, ConnectionId: sch.ConnectionID.String(), CreatedBy: sch.CreatedBy,
			CreateTime: timestamppb.New(sch.CreatedAt), LastStartTime: tsp(sch.LastStartedAt),
		}
	}
	return out, nil
}
