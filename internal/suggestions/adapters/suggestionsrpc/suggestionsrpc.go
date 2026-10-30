// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package suggestionsrpc serves SuggestionService over Connect (G0 M16
// D92). Handlers only translate: authentication, the coarse permission
// check and protovalidate have run before a handler is called, and the use
// cases check visibility per suggestion (HR-444) and the edition.
package suggestionsrpc

import (
	"context"
	"encoding/json/v2"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/suggestions/app"
	"github.com/katocxl/pantherclaw/internal/suggestions/domain"
)

// Handler serves SuggestionService.
type Handler struct {
	pantherclawv1connect.UnimplementedSuggestionServiceHandler
	svc *app.Service
}

// New returns the SuggestionService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

var states = map[domain.State]pb.SuggestionState{
	domain.Open: pb.SuggestionState_SUGGESTION_STATE_OPEN, domain.Drafted: pb.SuggestionState_SUGGESTION_STATE_DRAFTED,
	domain.Dismissed: pb.SuggestionState_SUGGESTION_STATE_DISMISSED, domain.Stale: pb.SuggestionState_SUGGESTION_STATE_STALE,
}

var uncertainties = map[domain.Uncertainty]pb.SuggestionUncertainty{
	domain.Low: pb.SuggestionUncertainty_SUGGESTION_UNCERTAINTY_LOW, domain.Medium: pb.SuggestionUncertainty_SUGGESTION_UNCERTAINTY_MEDIUM,
	domain.High: pb.SuggestionUncertainty_SUGGESTION_UNCERTAINTY_HIGH,
}

func stateOf(s pb.SuggestionState) domain.State {
	for k, v := range states {
		if v == s {
			return k
		}
	}
	return ""
}

func id(s string) (ids.UUID, error) {
	u, err := ids.ParseUUID(s)
	if err != nil {
		return u, app.ErrNotFound
	}
	return u, nil
}

// SuggestionPB renders a stored suggestion.
func SuggestionPB(s dbq.PcPolicySuggestion) *pb.Suggestion {
	out := &pb.Suggestion{
		Id: s.ID.String(), PostureFindingId: s.PostureFindingID.String(), GrantId: s.GrantID.String(), AgentId: s.AgentID.String(),
		WindowStartTime: timestamppb.New(s.WindowFrom), WindowEndTime: timestamppb.New(s.WindowTo),
		Uncertainty: uncertainties[domain.Uncertainty(s.Uncertainty)], UncertaintyReasons: s.UncertaintyReasons,
		State: states[domain.State(s.State)], CreateTime: timestamppb.New(s.CreatedAt), UpdateTime: timestamppb.New(s.UpdatedAt),
		Observed: map[string]int64{},
	}
	if domain.Kind(s.Kind) == domain.UnusedAuthority {
		out.Kind = pb.SuggestionKind_SUGGESTION_KIND_UNUSED_AUTHORITY
	}
	for _, o := range s.Owners {
		out.OwnerUserIds = append(out.OwnerUserIds, o.String())
	}
	// The columns are written by Generate in these shapes.
	_ = json.Unmarshal(s.Observed, &out.Observed)
	var limits []domain.Limit
	_ = json.Unmarshal(s.CoverageLimits, &limits)
	for _, l := range limits {
		out.CoverageLimits = append(out.CoverageLimits, &pb.SuggestionCoverageLimit{
			AgentId: l.Agent, ConnectionId: l.Connection, Operation: l.Operation, State: l.State,
		})
	}
	var rules []pdomain.Rule
	_ = json.Unmarshal(s.Proposed, &rules)
	for _, r := range rules {
		out.Proposed = append(out.Proposed, &pb.SuggestionRule{
			Id: r.ID, Kind: string(r.Kind), Summary: r.Summary, Operations: r.Operations, When: r.When, Reason: r.Reason,
		})
	}
	var e domain.Effect
	_ = json.Unmarshal(s.ExpectedEffect, &e)
	out.ExpectedEffect = &pb.SuggestionEffect{
		Collected: e.Collected, MatchingActions: e.MatchingActions, NewlyDenied: e.NewlyDenied, NewlyHeld: e.NewlyHeld,
		NotCollected: e.NotCollected,
	}
	if s.DraftPolicyVersionID != nil {
		out.DraftPolicyVersionId = s.DraftPolicyVersionID.String()
	}
	if s.DismissedBy != nil {
		out.DismissedBy = *s.DismissedBy
	}
	if s.DismissReason != nil {
		out.DismissReason = *s.DismissReason
	}
	return out
}

// ListSuggestions implements SuggestionServiceHandler.
func (h *Handler) ListSuggestions(ctx context.Context, req *pb.ListSuggestionsRequest) (*pb.ListSuggestionsResponse, error) {
	sts := make([]domain.State, 0, len(req.GetStates()))
	for _, s := range req.GetStates() {
		sts = append(sts, stateOf(s))
	}
	var kind domain.Kind
	if req.GetKind() == pb.SuggestionKind_SUGGESTION_KIND_UNUSED_AUTHORITY {
		kind = domain.UnusedAuthority
	}
	rows, next, err := h.svc.List(ctx, sts, kind, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pb.ListSuggestionsResponse{NextPageToken: next}
	for _, s := range rows {
		out.Suggestions = append(out.Suggestions, SuggestionPB(s))
	}
	return out, nil
}

// GetSuggestion implements SuggestionServiceHandler.
func (h *Handler) GetSuggestion(ctx context.Context, req *pb.GetSuggestionRequest) (*pb.GetSuggestionResponse, error) {
	sid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.Get(ctx, sid)
	if err != nil {
		return nil, err
	}
	return &pb.GetSuggestionResponse{Suggestion: SuggestionPB(s)}, nil
}

// DismissSuggestion implements SuggestionServiceHandler.
func (h *Handler) DismissSuggestion(ctx context.Context, req *pb.DismissSuggestionRequest) (*pb.DismissSuggestionResponse, error) {
	sid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.Dismiss(ctx, sid, req.GetReason())
	if err != nil {
		return nil, err
	}
	return &pb.DismissSuggestionResponse{Suggestion: SuggestionPB(s)}, nil
}

// DraftFromSuggestion implements SuggestionServiceHandler.
func (h *Handler) DraftFromSuggestion(ctx context.Context, req *pb.DraftFromSuggestionRequest) (*pb.DraftFromSuggestionResponse, error) {
	sid, err := id(req.GetId())
	if err != nil {
		return nil, err
	}
	s, n, err := h.svc.Draft(ctx, sid)
	if err != nil {
		return nil, err
	}
	out := &pb.DraftFromSuggestionResponse{Suggestion: SuggestionPB(s), PolicyVersion: int32(min(n, 1<<30))} //nolint:gosec // G115: bounded
	if s.DraftPolicyVersionID != nil {
		out.PolicyVersionId = s.DraftPolicyVersionID.String()
	}
	return out, nil
}
