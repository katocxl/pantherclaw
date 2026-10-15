// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package reflexrpc serves IncidentService and DetectionService over
// Connect (G0 M10 D9–D18).
package reflexrpc

import (
	"context"
	"encoding/json/v2"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// IncidentHandler serves IncidentService.
type IncidentHandler struct {
	pantherclawv1connect.UnimplementedIncidentServiceHandler
	svc *reflexapp.Incidents
}

// NewIncidents returns the IncidentService handler.
func NewIncidents(svc *reflexapp.Incidents) *IncidentHandler { return &IncidentHandler{svc: svc} }

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errInvalidID
	}
	return id, nil
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

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func idStr(id *ids.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func subjects(raw []byte) []*pb.ReflexSubject {
	subs, _ := reflexapp.Subjects(raw)
	return subjectsOf(subs)
}

func subjectsOf(subs []reflexdomain.Subject) []*pb.ReflexSubject {
	out := make([]*pb.ReflexSubject, 0, len(subs))
	for _, s := range subs {
		out = append(out, &pb.ReflexSubject{Type: string(s.Type), Id: s.ID})
	}
	return out
}

// AlertProto converts a stored alert.
func AlertProto(a dbq.PcAlert) *pb.Alert {
	facts := map[string]string{}
	_ = json.Unmarshal(a.Facts, &facts)
	return &pb.Alert{
		Id: a.ID.String(), Source: a.Source, RuleId: a.RuleID, RuleVersion: a.RuleVersion, RuleDigest: a.RuleDigest,
		PackVersion: a.PackVersion, Title: a.Title, Summary: a.Summary, Severity: a.Severity, Attention: a.Attention,
		Basis: a.Basis, Subjects: subjects(a.Subjects), Atlas: a.Atlas, Owasp: a.Owasp, Facts: facts, GroupKey: a.GroupKey,
		State: a.State, IncidentId: idStr(a.IncidentID), SuppressionId: idStr(a.SuppressionID), Count: a.Count,
		FirstSeenTime: ts(a.FirstSeen), LastSeenTime: ts(a.LastSeen), Test: a.Test,
	}
}

// IncidentProto converts a stored incident.
func IncidentProto(i dbq.PcIncident) *pb.Incident {
	return &pb.Incident{
		Id: i.ID.String(), Title: i.Title, Severity: i.Severity, State: i.State, OwnerId: idStr(i.OwnerID),
		GroupKey: i.GroupKey, OpenedBy: i.OpenedBy, CreateTime: ts(i.CreatedAt), UpdateTime: ts(i.UpdatedAt),
	}
}

func alertEvents(es []dbq.PcAlertEvent) []*pb.ReflexEvent {
	out := make([]*pb.ReflexEvent, 0, len(es))
	for _, e := range es {
		out = append(out, &pb.ReflexEvent{
			Id: e.ID.String(), Kind: e.Kind, ActorType: e.ActorType, ActorId: e.ActorID, FromValue: str(e.FromValue),
			ToValue: str(e.ToValue), Note: str(e.Note), CreateTime: ts(e.CreatedAt),
		})
	}
	return out
}

func incidentEvents(es []dbq.PcIncidentEvent) []*pb.ReflexEvent {
	out := make([]*pb.ReflexEvent, 0, len(es))
	for _, e := range es {
		out = append(out, &pb.ReflexEvent{
			Id: e.ID.String(), Kind: e.Kind, ActorType: e.ActorType, ActorId: e.ActorID, FromValue: str(e.FromValue),
			ToValue: str(e.ToValue), AlertId: idStr(e.AlertID), Note: str(e.Note), CreateTime: ts(e.CreatedAt),
		})
	}
	return out
}

func alertList(as []dbq.PcAlert) []*pb.Alert {
	out := make([]*pb.Alert, 0, len(as))
	for _, a := range as {
		out = append(out, AlertProto(a))
	}
	return out
}

// ListAlerts implements IncidentServiceHandler.
func (h *IncidentHandler) ListAlerts(ctx context.Context, req *pb.ListAlertsRequest) (*pb.ListAlertsResponse, error) {
	f := reflexapp.AlertFilter{States: req.GetStates(), Rule: req.GetRuleId()}
	if req.IncidentId != nil {
		id, err := idOf(req.GetIncidentId())
		if err != nil {
			return nil, err
		}
		f.Incident = &id
	}
	p, err := h.svc.ListAlerts(ctx, f, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	return &pb.ListAlertsResponse{Alerts: alertList(p.Items), NextPageToken: p.Next}, nil
}

// GetAlert implements IncidentServiceHandler.
func (h *IncidentHandler) GetAlert(ctx context.Context, req *pb.GetAlertRequest) (*pb.GetAlertResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.GetAlert(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.GetAlertResponse{Alert: AlertProto(d.Alert), Events: alertEvents(d.Events), PossibleRelated: alertList(d.Related)}
	for _, e := range d.Evidence {
		out.Evidence = append(out.Evidence, &pb.AlertEvidence{Kind: e.Kind, Id: e.RefID.String(), OccurTime: ts(e.OccurredAt)})
	}
	return out, nil
}

// SetAlertState implements IncidentServiceHandler.
func (h *IncidentHandler) SetAlertState(ctx context.Context, req *pb.SetAlertStateRequest) (*pb.SetAlertStateResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	a, err := h.svc.SetAlertState(ctx, id, req.GetState(), req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.SetAlertStateResponse{Alert: AlertProto(a)}, nil
}

// PromoteAlert implements IncidentServiceHandler.
func (h *IncidentHandler) PromoteAlert(ctx context.Context, req *pb.PromoteAlertRequest) (*pb.PromoteAlertResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	i, err := h.svc.PromoteAlert(ctx, id, req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.PromoteAlertResponse{Incident: IncidentProto(i)}, nil
}

// LinkAlert implements IncidentServiceHandler.
func (h *IncidentHandler) LinkAlert(ctx context.Context, req *pb.LinkAlertRequest) (*pb.LinkAlertResponse, error) {
	a, err := idOf(req.GetAlertId())
	if err != nil {
		return nil, err
	}
	i, err := idOf(req.GetIncidentId())
	if err != nil {
		return nil, err
	}
	out, err := h.svc.LinkAlert(ctx, a, i)
	if err != nil {
		return nil, err
	}
	return &pb.LinkAlertResponse{Alert: AlertProto(out)}, nil
}

// ListIncidents implements IncidentServiceHandler.
func (h *IncidentHandler) ListIncidents(ctx context.Context, req *pb.ListIncidentsRequest) (*pb.ListIncidentsResponse, error) {
	p, err := h.svc.ListIncidents(ctx, req.GetStates(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListIncidentsResponse{NextPageToken: p.Next}
	for _, i := range p.Items {
		out.Incidents = append(out.Incidents, IncidentProto(i))
	}
	return out, nil
}

// GetIncident implements IncidentServiceHandler.
func (h *IncidentHandler) GetIncident(ctx context.Context, req *pb.GetIncidentRequest) (*pb.GetIncidentResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.svc.GetIncident(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pb.GetIncidentResponse{Incident: IncidentProto(d.Incident), Alerts: alertList(d.Alerts), Events: incidentEvents(d.Events)}
	for _, g := range d.Retries {
		out.RetryGroups = append(out.RetryGroups, &pb.RetryGroup{
			TransactionId: g.Transaction.String(), Count: int32(g.Count), //nolint:gosec // bounded by alert counts
			FirstTime: ts(g.First), LatestTime: ts(g.Latest), Executed: g.Executed,
		})
	}
	return out, nil
}

// AssignIncident implements IncidentServiceHandler.
func (h *IncidentHandler) AssignIncident(ctx context.Context, req *pb.AssignIncidentRequest) (*pb.AssignIncidentResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	owner, err := idOf(req.GetOwnerId())
	if err != nil {
		return nil, err
	}
	i, err := h.svc.AssignIncident(ctx, id, owner)
	if err != nil {
		return nil, err
	}
	return &pb.AssignIncidentResponse{Incident: IncidentProto(i)}, nil
}

// SetIncidentState implements IncidentServiceHandler.
func (h *IncidentHandler) SetIncidentState(ctx context.Context, req *pb.SetIncidentStateRequest) (*pb.SetIncidentStateResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	i, err := h.svc.SetIncidentState(ctx, id, req.GetState(), req.GetNote())
	if err != nil {
		return nil, err
	}
	return &pb.SetIncidentStateResponse{Incident: IncidentProto(i)}, nil
}

func suppressionProto(s reflexapp.Suppression) *pb.Suppression {
	return &pb.Suppression{
		Id: s.ID.String(), RuleId: s.RuleID, Subjects: subjects(s.Subjects), MaxSeverity: s.MaxSeverity, Reason: s.Reason,
		CreatedBy: s.CreatedBy.String(), CreateTime: ts(s.CreatedAt), ExpireTime: ts(s.ExpiresAt), EndTime: tsp(s.EndedAt),
		EndedBy: idStr(s.EndedBy), EndReason: str(s.EndReason), BrokenSubjects: s.Broken,
	}
}

// CreateSuppression implements IncidentServiceHandler.
func (h *IncidentHandler) CreateSuppression(ctx context.Context, req *pb.CreateSuppressionRequest) (*pb.CreateSuppressionResponse, error) {
	r := reflexapp.SuppressionRequest{
		Rule: req.GetRuleId(), MaxSeverity: reflexdomain.Severity(req.GetMaxSeverity()), Reason: req.GetReason(),
		ExpiresIn: time.Duration(req.GetExpiresInSeconds()) * time.Second,
	}
	for _, s := range req.GetSubjects() {
		r.Subjects = append(r.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectType(s.GetType()), ID: s.GetId()})
	}
	s, err := h.svc.CreateSuppression(ctx, r)
	if err != nil {
		return nil, err
	}
	return &pb.CreateSuppressionResponse{Suppression: suppressionProto(s)}, nil
}

// ListSuppressions implements IncidentServiceHandler.
func (h *IncidentHandler) ListSuppressions(ctx context.Context, req *pb.ListSuppressionsRequest) (*pb.ListSuppressionsResponse, error) {
	p, err := h.svc.ListSuppressions(ctx, req.GetActiveOnly(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListSuppressionsResponse{NextPageToken: p.Next}
	for _, s := range p.Items {
		out.Suppressions = append(out.Suppressions, suppressionProto(s))
	}
	return out, nil
}

// EndSuppression implements IncidentServiceHandler.
func (h *IncidentHandler) EndSuppression(ctx context.Context, req *pb.EndSuppressionRequest) (*pb.EndSuppressionResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.EndSuppression(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.EndSuppressionResponse{Suppression: suppressionProto(s)}, nil
}

// FailureProto converts a stored failure.
func FailureProto(f dbq.PcOperationalFailure) *pb.OperationalFailure {
	out := &pb.OperationalFailure{
		Id: f.ID.String(), Kind: f.Kind, Summary: f.Summary, NextStep: f.NextStep, Scope: subjects(f.Scope),
		Deadline: ts(f.Deadline), State: f.State, Count: f.Count, FirstSeenTime: ts(f.FirstSeen), LastSeenTime: ts(f.LastSeen),
		ResolvedBy: idStr(f.ResolvedBy), ResolveTime: tsp(f.ResolvedAt), Resolution: str(f.Resolution),
	}
	if f.OwnerType != nil && f.OwnerID != nil {
		out.Owner = &pb.ReflexSubject{Type: *f.OwnerType, Id: *f.OwnerID}
	}
	return out
}

// ListFailures implements IncidentServiceHandler.
func (h *IncidentHandler) ListFailures(ctx context.Context, req *pb.ListFailuresRequest) (*pb.ListFailuresResponse, error) {
	p, err := h.svc.ListFailures(ctx, req.GetStates(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListFailuresResponse{NextPageToken: p.Next}
	for _, f := range p.Items {
		out.Failures = append(out.Failures, FailureProto(f))
	}
	return out, nil
}

// AssignFailure implements IncidentServiceHandler.
func (h *IncidentHandler) AssignFailure(ctx context.Context, req *pb.AssignFailureRequest) (*pb.AssignFailureResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	owner, err := idOf(req.GetOwnerId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.AssignFailure(ctx, id, owner)
	if err != nil {
		return nil, err
	}
	return &pb.AssignFailureResponse{Failure: FailureProto(f)}, nil
}

// ResolveFailure implements IncidentServiceHandler.
func (h *IncidentHandler) ResolveFailure(ctx context.Context, req *pb.ResolveFailureRequest) (*pb.ResolveFailureResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	f, err := h.svc.ResolveFailure(ctx, id, req.GetResolution())
	if err != nil {
		return nil, err
	}
	return &pb.ResolveFailureResponse{Failure: FailureProto(f)}, nil
}
