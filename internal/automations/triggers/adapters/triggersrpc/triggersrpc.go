// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package triggersrpc serves TriggerService over Connect (G0 M11 part 2
// D16–D23, D53, D59; HR-275..278). Calls that need a step-up pass none, so
// the use cases answer STEP_UP_REQUIRED and the confirm pages make them.
package triggersrpc

import (
	"context"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Page paths (the confirm pages, internal/authn/adapters/webhttp).
const (
	SourcesPage      = "/automations/sources/"
	DestinationsPage = "/automations/destinations/"
)

// Handler serves TriggerService.
type Handler struct {
	pantherclawv1connect.UnimplementedTriggerServiceHandler
	trig      *triggers.Service
	ep        *endpoints.Service
	publicURL string
}

// New returns the handler; publicURL builds endpoint and page links.
func New(trig *triggers.Service, ep *endpoints.Service, publicURL string) *Handler {
	return &Handler{trig: trig, ep: ep, publicURL: strings.TrimRight(publicURL, "/")}
}

var errInvalidID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "invalid id")

func idOf(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil || id.IsZero() {
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
	return ts(*t)
}

func str(u *ids.UUID) string {
	if u == nil || u.IsZero() {
		return ""
	}
	return u.String()
}

// PreviewSchedule implements TriggerServiceHandler.
func (h *Handler) PreviewSchedule(ctx context.Context, req *pantherclawv1.PreviewScheduleRequest) (*pantherclawv1.PreviewScheduleResponse, error) {
	var from time.Time
	if req.GetFrom() != nil {
		from = req.GetFrom().AsTime()
	}
	occ, err := h.trig.Preview(ctx, req.GetCron(), req.GetTimezone(), req.GetDstGap() == "SHIFT", from, int(req.GetCount()))
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.PreviewScheduleResponse{DaysNote: triggers.DaysNote(req.GetCron())}
	for _, o := range occ {
		out.Occurrences = append(out.Occurrences, &pantherclawv1.ScheduleOccurrence{Local: o.Local, Utc: ts(o.UTC), Note: string(o.Note)})
	}
	return out, nil
}

func (h *Handler) outcome(ctx context.Context, o triggers.Outcome) (*pantherclawv1.Trigger, error) {
	r, err := h.trig.GetTrigger(ctx, o.Trigger)
	if err != nil {
		// The caller may run automations without reading them.
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			return &pantherclawv1.Trigger{Id: o.Trigger.String(), State: string(o.State), Reason: o.Reason, ExecutionId: o.Execution.String()}, nil
		}
		return nil, err
	}
	return triggerProto(r), nil
}

// StartExecution implements TriggerServiceHandler.
func (h *Handler) StartExecution(ctx context.Context, req *pantherclawv1.StartExecutionRequest) (*pantherclawv1.StartExecutionResponse, error) {
	id, err := idOf(req.GetAutomationId())
	if err != nil {
		return nil, err
	}
	o, err := h.trig.StartExecution(ctx, triggers.ManualStart{Automation: id, Params: req.GetParams(), IdempotencyKey: req.GetIdempotencyKey()}, nil)
	if err != nil {
		return nil, err
	}
	t, err := h.outcome(ctx, o)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartExecutionResponse{Trigger: t}, nil
}

// RetryExecution implements TriggerServiceHandler.
func (h *Handler) RetryExecution(ctx context.Context, req *pantherclawv1.RetryExecutionRequest) (*pantherclawv1.RetryExecutionResponse, error) {
	id, err := idOf(req.GetExecutionId())
	if err != nil {
		return nil, err
	}
	o, err := h.trig.RetryExecution(ctx, id, req.GetIdempotencyKey(), nil)
	if err != nil {
		return nil, err
	}
	t, err := h.outcome(ctx, o)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetryExecutionResponse{Trigger: t}, nil
}

func triggerProto(r triggers.Record) *pantherclawv1.Trigger {
	t := &pantherclawv1.Trigger{
		Id: r.ID.String(), AutomationId: r.Automation.String(), VersionId: r.Version.String(), Kind: r.Kind, Mode: r.Mode,
		SourceRef: r.SourceRef, Authenticity: r.Authenticity, AuthenticityDetail: r.Detail, Params: r.Params, State: r.State,
		Reason: r.Reason, ExecutionId: str(r.Execution), RootTriggerId: r.Root.String(), Depth: int32(r.Depth), //nolint:gosec // 0..4
		RetriedFrom: str(r.RetriedFrom), OccurTime: ts(r.OccurredAt), ReceiveTime: ts(r.ReceivedAt),
	}
	for _, a := range r.Ancestry {
		t.Ancestry = append(t.Ancestry, a.String())
	}
	return t
}

// GetTrigger implements TriggerServiceHandler.
func (h *Handler) GetTrigger(ctx context.Context, req *pantherclawv1.GetTriggerRequest) (*pantherclawv1.GetTriggerResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	r, err := h.trig.GetTrigger(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetTriggerResponse{Trigger: triggerProto(r)}, nil
}

// ListTriggers implements TriggerServiceHandler.
func (h *Handler) ListTriggers(ctx context.Context, req *pantherclawv1.ListTriggersRequest) (*pantherclawv1.ListTriggersResponse, error) {
	id, err := idOf(req.GetAutomationId())
	if err != nil {
		return nil, err
	}
	rows, next, err := h.trig.ListTriggers(ctx, id, req.GetState(), int(req.GetPageSize()), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListTriggersResponse{NextPageToken: next}
	for _, r := range rows {
		out.Triggers = append(out.Triggers, triggerProto(r))
	}
	return out, nil
}

func (h *Handler) sourceProto(ctx context.Context, s endpoints.Source) *pantherclawv1.EventSource {
	org := ""
	if c, err := tenancy.CallerFrom(ctx); err == nil {
		org = c.Org.String()
	}
	return &pantherclawv1.EventSource{
		Id: s.ID.String(), Name: s.Name, Description: s.Description, Types: s.Types, RatePerMinute: int32(s.RatePerMinute), //nolint:gosec // ≤ 600
		State: s.State, CreatedBy: s.CreatedBy.String(), CreateTime: ts(s.CreatedAt), ActivatedBy: str(s.ActivatedBy),
		ActivateTime:    tsp(s.ActivatedAt),
		EndpointUrl:     h.publicURL + "/v1/automations/events/" + org + "/" + s.ID.String(),
		ConfirmUrl:      h.publicURL + SourcesPage + s.ID.String() + "/confirm?org=" + org,
		RotationEndTime: tsp(s.RotationEndsAt),
	}
}

func (h *Handler) destinationProto(ctx context.Context, d endpoints.Destination) *pantherclawv1.AutomationDestination {
	org := ""
	if c, err := tenancy.CallerFrom(ctx); err == nil {
		org = c.Org.String()
	}
	return &pantherclawv1.AutomationDestination{
		Id: d.ID.String(), Name: d.Name, Url: d.URL, Internal: d.Internal, Purposes: d.Purposes, State: d.State,
		CreatedBy: d.CreatedBy.String(), CreateTime: ts(d.CreatedAt), ActivatedBy: str(d.ActivatedBy),
		ActivateTime: tsp(d.ActivatedAt), ConfirmUrl: h.publicURL + DestinationsPage + d.ID.String() + "/confirm?org=" + org,
		RotationEndTime: tsp(d.RotationEndsAt),
	}
}

// CreateEventSource implements TriggerServiceHandler.
func (h *Handler) CreateEventSource(ctx context.Context, req *pantherclawv1.CreateEventSourceRequest) (*pantherclawv1.CreateEventSourceResponse, error) {
	c, err := h.ep.CreateEventSource(ctx, endpoints.NewSource{
		Name: req.GetName(), Description: req.GetDescription(), Types: req.GetTypes(), RatePerMinute: int(req.GetRatePerMinute()),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateEventSourceResponse{Source: h.sourceProto(ctx, c.Source), SigningSecret: c.Secret}, nil
}

// ActivateEventSource implements TriggerServiceHandler: always
// STEP_UP_REQUIRED over the API (D53).
func (h *Handler) ActivateEventSource(ctx context.Context, req *pantherclawv1.ActivateEventSourceRequest) (*pantherclawv1.ActivateEventSourceResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.ep.ActivateEventSource(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivateEventSourceResponse{Source: h.sourceProto(ctx, s)}, nil
}

// RotateEventSourceSecret implements TriggerServiceHandler: always
// STEP_UP_REQUIRED over the API (D53).
func (h *Handler) RotateEventSourceSecret(ctx context.Context, req *pantherclawv1.RotateEventSourceSecretRequest) (*pantherclawv1.RotateEventSourceSecretResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	secret, err := h.ep.RotateEventSourceSecret(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateEventSourceSecretResponse{SigningSecret: secret}, nil
}

// DisableEventSource implements TriggerServiceHandler.
func (h *Handler) DisableEventSource(ctx context.Context, req *pantherclawv1.DisableEventSourceRequest) (*pantherclawv1.DisableEventSourceResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.ep.DisableEventSource(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableEventSourceResponse{Source: h.sourceProto(ctx, s)}, nil
}

// GetEventSource implements TriggerServiceHandler.
func (h *Handler) GetEventSource(ctx context.Context, req *pantherclawv1.GetEventSourceRequest) (*pantherclawv1.GetEventSourceResponse, error) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.ep.GetEventSource(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEventSourceResponse{Source: h.sourceProto(ctx, s)}, nil
}

// ListEventSources implements TriggerServiceHandler.
func (h *Handler) ListEventSources(ctx context.Context, _ *pantherclawv1.ListEventSourcesRequest) (*pantherclawv1.ListEventSourcesResponse, error) {
	rows, err := h.ep.ListEventSources(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListEventSourcesResponse{}
	for _, s := range rows {
		out.Sources = append(out.Sources, h.sourceProto(ctx, s))
	}
	return out, nil
}

// CreateAutomationDestination implements TriggerServiceHandler.
func (h *Handler) CreateAutomationDestination(ctx context.Context, req *pantherclawv1.CreateAutomationDestinationRequest) (
	*pantherclawv1.CreateAutomationDestinationResponse, error,
) {
	c, err := h.ep.CreateDestination(ctx, endpoints.NewDestination{
		Name: req.GetName(), URL: req.GetUrl(), Internal: req.GetInternal(), Purposes: req.GetPurposes(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateAutomationDestinationResponse{Destination: h.destinationProto(ctx, c.Destination), SigningSecret: c.Secret}, nil
}

// ActivateAutomationDestination implements TriggerServiceHandler: always
// STEP_UP_REQUIRED over the API (D53).
func (h *Handler) ActivateAutomationDestination(ctx context.Context, req *pantherclawv1.ActivateAutomationDestinationRequest) (
	*pantherclawv1.ActivateAutomationDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.ep.ActivateDestination(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ActivateAutomationDestinationResponse{Destination: h.destinationProto(ctx, d)}, nil
}

// RotateAutomationDestinationSecret implements TriggerServiceHandler:
// always STEP_UP_REQUIRED over the API (D53).
func (h *Handler) RotateAutomationDestinationSecret(ctx context.Context, req *pantherclawv1.RotateAutomationDestinationSecretRequest) (
	*pantherclawv1.RotateAutomationDestinationSecretResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	secret, err := h.ep.RotateDestinationSecret(ctx, id, nil)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RotateAutomationDestinationSecretResponse{SigningSecret: secret}, nil
}

// SetAutomationDestinationState implements TriggerServiceHandler.
func (h *Handler) SetAutomationDestinationState(ctx context.Context, req *pantherclawv1.SetAutomationDestinationStateRequest) (
	*pantherclawv1.SetAutomationDestinationStateResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.ep.SetDestinationState(ctx, id, req.GetState())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SetAutomationDestinationStateResponse{Destination: h.destinationProto(ctx, d)}, nil
}

// GetAutomationDestination implements TriggerServiceHandler.
func (h *Handler) GetAutomationDestination(ctx context.Context, req *pantherclawv1.GetAutomationDestinationRequest) (
	*pantherclawv1.GetAutomationDestinationResponse, error,
) {
	id, err := idOf(req.GetId())
	if err != nil {
		return nil, err
	}
	d, err := h.ep.GetDestination(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetAutomationDestinationResponse{Destination: h.destinationProto(ctx, d)}, nil
}

// ListAutomationDestinations implements TriggerServiceHandler.
func (h *Handler) ListAutomationDestinations(ctx context.Context, _ *pantherclawv1.ListAutomationDestinationsRequest) (
	*pantherclawv1.ListAutomationDestinationsResponse, error,
) {
	rows, err := h.ep.ListDestinations(ctx)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAutomationDestinationsResponse{}
	for _, d := range rows {
		out.Destinations = append(out.Destinations, h.destinationProto(ctx, d))
	}
	return out, nil
}
