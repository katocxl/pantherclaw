// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package waitlistrpc serves WaitlistService over Connect (PN-004): the
// Agent Waitlist's entries, assignment, access requests, escalation chains
// and settings (G0 M5 part 2). Entries are decided by the service that owns
// their subject, never here.
package waitlistrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/app"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Waitlist serves WaitlistService.
type Waitlist struct {
	pantherclawv1connect.UnimplementedWaitlistServiceHandler
	r *app.Reader
	w *app.Writer
}

// NewWaitlist returns the WaitlistService handler (reads only until
// WithWriter).
func NewWaitlist(r *app.Reader) *Waitlist { return &Waitlist{r: r} }

// WithWriter adds the writes: assignment, access requests, chains and
// settings.
func (s *Waitlist) WithWriter(w *app.Writer) *Waitlist {
	s.w = w
	return s
}

var (
	errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")
	errReadOnly  = pcerr.New(pcerr.Unimplemented, "UNIMPLEMENTED", "this server serves waitlist reads only")
)

func parseID(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil || u.Version() != 7 {
		return ids.UUID{}, errInvalidID
	}
	return u, nil
}

func optionalID(s *string) (*ids.UUID, error) {
	if s == nil {
		return nil, nil
	}
	u, err := parseID(*s)
	return &u, err
}

var stateToProto = map[string]pantherclawv1.WaitlistState{
	"OPEN":      pantherclawv1.WaitlistState_WAITLIST_STATE_OPEN,
	"APPROVED":  pantherclawv1.WaitlistState_WAITLIST_STATE_APPROVED,
	"REJECTED":  pantherclawv1.WaitlistState_WAITLIST_STATE_REJECTED,
	"EXPIRED":   pantherclawv1.WaitlistState_WAITLIST_STATE_EXPIRED,
	"CANCELLED": pantherclawv1.WaitlistState_WAITLIST_STATE_CANCELLED, //nolint:misspell // stored value
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

func idOrEmpty(u ids.UUID) string {
	if u.IsZero() {
		return ""
	}
	return u.String()
}

func entryProto(e app.Entry) *pantherclawv1.WaitlistEntry {
	return &pantherclawv1.WaitlistEntry{
		Id: e.ID.String(), Kind: pantherclawv1.WaitlistKind(pantherclawv1.WaitlistKind_value["WAITLIST_KIND_"+e.Kind]),
		SubjectType: e.SubjectType, SubjectId: e.SubjectID.String(), AgentId: idOrEmpty(e.AgentID), State: stateToProto[e.State],
		Evidence: e.Evidence, UntrustedEvidence: e.Untrusted, DeadlineTime: ts(&e.DeadlineAt), DecidedBy: e.DecidedBy,
		DecideTime: ts(e.DecidedAt), DecisionReason: e.DecisionReason, CreateTime: ts(&e.CreatedAt),
		Priority: int32(e.Priority), RunId: idOrEmpty(e.RunID), TransactionId: idOrEmpty(e.TransactionID), //nolint:gosec // 1..4
		RequestedBy: e.RequestedBy, RoutingHealth: pantherclawv1.RoutingHealth(pantherclawv1.RoutingHealth_value["ROUTING_HEALTH_"+e.RoutingHealth]),
		EscalationStep: int32(e.EscalationStep), NextStepTime: ts(e.NextStepAt), AssigneeUserId: idOrEmpty(e.Assignee), //nolint:gosec // ≤ 5
		AssignTime: ts(e.AssignedAt), FirstResponseTime: ts(e.FirstResponseAt),
	}
}

// scope names a binding: "approver@TEAM:<id>", or "approver@ORG".
func scope(b td.Binding) string {
	s := string(b.Role) + "@" + string(b.Scope.Type)
	if b.Scope.Type != td.ScopeOrg {
		s += ":" + b.Scope.ID.String()
	}
	return s
}

// ListWaitlistEntries implements WaitlistServiceHandler.
func (s *Waitlist) ListWaitlistEntries(ctx context.Context, req *pantherclawv1.ListWaitlistEntriesRequest) (*pantherclawv1.ListWaitlistEntriesResponse, error) {
	pr, err := page.Parse(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	f := app.Filter{AssignedToMe: req.GetAssignedToMe(), Overdue: req.GetOverdue()}
	if req.AgentId != nil {
		if f.Agent, err = parseID(req.GetAgentId()); err != nil {
			return nil, err
		}
	}
	for _, st := range req.GetStates() {
		for k, v := range stateToProto {
			if v == st {
				f.States = append(f.States, k)
			}
		}
	}
	for _, k := range req.GetKinds() {
		f.Kinds = append(f.Kinds, strings.TrimPrefix(k.String(), "WAITLIST_KIND_"))
	}
	for _, p := range req.GetPriorities() {
		f.Priorities = append(f.Priorities, int(p))
	}
	p, err := s.r.List(ctx, pr, f)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListWaitlistEntriesResponse{NextPageToken: p.Next}
	for _, e := range p.Items {
		out.Entries = append(out.Entries, entryProto(e))
	}
	for _, b := range p.Scopes {
		out.CheckedScopes = append(out.CheckedScopes, scope(b))
	}
	return out, nil
}

// GetWaitlistEntry implements WaitlistServiceHandler.
func (s *Waitlist) GetWaitlistEntry(ctx context.Context, req *pantherclawv1.GetWaitlistEntryRequest) (*pantherclawv1.GetWaitlistEntryResponse, error) {
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetWaitlistEntryResponse{Entry: entryProto(e)}, nil
}

// AssignWaitlistEntry implements WaitlistServiceHandler.
func (s *Waitlist) AssignWaitlistEntry(ctx context.Context, req *pantherclawv1.AssignWaitlistEntryRequest) (*pantherclawv1.AssignWaitlistEntryResponse, error) {
	if s.w == nil {
		return nil, errReadOnly
	}
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.w.Assign(ctx, id, req.GetUnassign())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.AssignWaitlistEntryResponse{Entry: entryProto(e)}, nil
}

// RequestAccess implements WaitlistServiceHandler.
func (s *Waitlist) RequestAccess(ctx context.Context, req *pantherclawv1.RequestAccessRequest) (*pantherclawv1.RequestAccessResponse, error) {
	if s.w == nil {
		return nil, errReadOnly
	}
	run, err := parseID(req.GetRunId())
	if err != nil {
		return nil, err
	}
	txn, err := optionalID(req.TransactionId)
	if err != nil {
		return nil, err
	}
	e, err := s.w.RequestAccess(ctx, run, req.GetNote(), txn)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestAccessResponse{Entry: entryProto(e)}, nil
}

// DismissAccessRequest implements WaitlistServiceHandler.
func (s *Waitlist) DismissAccessRequest(ctx context.Context, req *pantherclawv1.DismissAccessRequestRequest) (*pantherclawv1.DismissAccessRequestResponse, error) {
	if s.w == nil {
		return nil, errReadOnly
	}
	id, err := parseID(req.GetId())
	if err != nil {
		return nil, err
	}
	e, err := s.w.DismissAccessRequest(ctx, id, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DismissAccessRequestResponse{Entry: entryProto(e)}, nil
}

func chainProto(c app.Chain) *pantherclawv1.EscalationChain {
	out := &pantherclawv1.EscalationChain{
		TeamId: idOrEmpty(c.Team), Revision: int32(c.Revision), CreatedBy: c.CreatedBy, CreateTime: ts(&c.CreatedAt), //nolint:gosec // small
	}
	for _, st := range c.Steps {
		out.Steps = append(out.Steps, &pantherclawv1.EscalationStep{
			AtPercent: int32(st.AtPercent), //nolint:gosec // 0..99
			Scope:     pantherclawv1.EscalationScope(pantherclawv1.EscalationScope_value["ESCALATION_SCOPE_"+st.Scope]),
			Remind:    st.Remind, NotifyOwners: st.NotifyOwners, NotifyChannels: st.NotifyChannels,
		})
	}
	return out
}

// GetEscalationChain implements WaitlistServiceHandler.
func (s *Waitlist) GetEscalationChain(ctx context.Context, req *pantherclawv1.GetEscalationChainRequest) (*pantherclawv1.GetEscalationChainResponse, error) {
	team, err := optionalID(req.TeamId)
	if err != nil {
		return nil, err
	}
	c, err := s.r.GetEscalationChain(ctx, team)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEscalationChainResponse{Chain: chainProto(c)}, nil
}

// SetEscalationChain implements WaitlistServiceHandler.
func (s *Waitlist) SetEscalationChain(ctx context.Context, req *pantherclawv1.SetEscalationChainRequest) (*pantherclawv1.SetEscalationChainResponse, error) {
	if s.w == nil {
		return nil, errReadOnly
	}
	team, err := optionalID(req.TeamId)
	if err != nil {
		return nil, err
	}
	var steps []wdomain.Step
	for _, st := range req.GetSteps() {
		steps = append(steps, wdomain.Step{
			AtPercent: int(st.GetAtPercent()), Scope: strings.TrimPrefix(st.GetScope().String(), "ESCALATION_SCOPE_"),
			Remind: st.GetRemind(), NotifyOwners: st.GetNotifyOwners(), NotifyChannels: st.GetNotifyChannels(),
		})
	}
	c, err := s.w.SetEscalationChain(ctx, team, steps, int(req.GetRevision()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetEscalationChainResponse{Chain: chainProto(c)}, nil
}

func settingsProto(st app.Settings) *pantherclawv1.WaitlistSettings {
	return &pantherclawv1.WaitlistSettings{
		BatchCeilings: st.BatchCeilings, HoldDeadlineSeconds: st.HoldDeadline, ConsumeWindowSeconds: st.ConsumeWindow,
		AccessRequestDeadlineSeconds: st.AccessRequestDeadline, ToolReviewDeadlineSeconds: st.ToolReviewDeadline,
		RestorationDeadlineSeconds: st.RestorationDeadline, ReconciliationDeadlineSeconds: st.ReconciliationDeadline,
		MaxHoldsPerGrant: st.MaxHoldsPerGrant, MaxHoldsPerRun: st.MaxHoldsPerRun, MinAccountAgeSeconds: st.MinAccountAge,
		MinRoleAgeSeconds: st.MinRoleAge, MinCredentialAgeSeconds: st.MinCredentialAge, SelfGrantDelaySeconds: st.SelfGrantDelay,
		UpdatedBy: st.UpdatedBy, UpdateTime: ts(&st.UpdatedAt),
	}
}

// GetWaitlistSettings implements WaitlistServiceHandler.
func (s *Waitlist) GetWaitlistSettings(ctx context.Context, _ *pantherclawv1.GetWaitlistSettingsRequest) (*pantherclawv1.GetWaitlistSettingsResponse, error) {
	st, err := s.r.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetWaitlistSettingsResponse{Settings: settingsProto(st)}, nil
}

// UpdateWaitlistSettings implements WaitlistServiceHandler.
func (s *Waitlist) UpdateWaitlistSettings(ctx context.Context, req *pantherclawv1.UpdateWaitlistSettingsRequest) (*pantherclawv1.UpdateWaitlistSettingsResponse, error) {
	if s.w == nil {
		return nil, errReadOnly
	}
	in := req.GetSettings()
	if in == nil {
		return nil, errors.New("waitlistrpc: no settings")
	}
	st, err := s.w.UpdateSettings(ctx, app.Settings{
		BatchCeilings: in.GetBatchCeilings(), HoldDeadline: in.GetHoldDeadlineSeconds(), ConsumeWindow: in.GetConsumeWindowSeconds(),
		AccessRequestDeadline: in.GetAccessRequestDeadlineSeconds(), ToolReviewDeadline: in.GetToolReviewDeadlineSeconds(),
		RestorationDeadline: in.GetRestorationDeadlineSeconds(), ReconciliationDeadline: in.GetReconciliationDeadlineSeconds(),
		MaxHoldsPerGrant: in.GetMaxHoldsPerGrant(), MaxHoldsPerRun: in.GetMaxHoldsPerRun(), MinAccountAge: in.GetMinAccountAgeSeconds(),
		MinRoleAge: in.GetMinRoleAgeSeconds(), MinCredentialAge: in.GetMinCredentialAgeSeconds(), SelfGrantDelay: in.GetSelfGrantDelaySeconds(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateWaitlistSettingsResponse{Settings: settingsProto(st)}, nil
}

func metricProto(m app.Metric) *pantherclawv1.WaitlistMetric {
	return &pantherclawv1.WaitlistMetric{
		Kind: pantherclawv1.WaitlistKind(pantherclawv1.WaitlistKind_value["WAITLIST_KIND_"+m.Kind]), DeciderUserId: idOrEmpty(m.Decider),
		Count: m.Entries, Decided: m.Decided, FirstResponseP50Seconds: m.FirstResponseP50, FirstResponseP90Seconds: m.FirstResponseP90,
		DecisionP50Seconds: m.DecisionP50, DecisionP90Seconds: m.DecisionP90, ExpiryRate: m.ExpiryRate, EscalationRate: m.EscalationRate,
		RoutingFailures: m.RoutingFailures,
	}
}

// GetWaitlistMetrics implements WaitlistServiceHandler (Team).
func (s *Waitlist) GetWaitlistMetrics(ctx context.Context, req *pantherclawv1.GetWaitlistMetricsRequest) (*pantherclawv1.GetWaitlistMetricsResponse, error) {
	var kinds []string
	for _, k := range req.GetKinds() {
		kinds = append(kinds, strings.TrimPrefix(k.String(), "WAITLIST_KIND_"))
	}
	m, err := s.r.Metrics(ctx, int(req.GetWindowDays()), kinds)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetWaitlistMetricsResponse{StartTime: ts(&m.Start), EndTime: ts(&m.End)}
	for _, x := range m.ByKind {
		out.ByKind = append(out.ByKind, metricProto(x))
	}
	for _, x := range m.ByDecider {
		out.ByDecider = append(out.ByDecider, metricProto(x))
	}
	return out, nil
}
