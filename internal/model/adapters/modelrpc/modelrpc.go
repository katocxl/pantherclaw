// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package modelrpc serves ModelService (G0 M21 D304, D309). It has no way to
// turn drafting on or to set a key, and no response carries a key.
package modelrpc

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/search"
	"github.com/katocxl/pantherclaw/internal/search/adapters/searchrpc"
)

// Handler implements ModelServiceHandler.
type Handler struct {
	svc     *app.Service
	drafter *search.Drafter
}

var _ pantherclawv1connect.ModelServiceHandler = (*Handler)(nil)

// New returns the handler.
func New(svc *app.Service, drafter *search.Drafter) *Handler {
	return &Handler{svc: svc, drafter: drafter}
}

func (h *Handler) settings(s app.Settings) *pantherclawv1.ModelSettings {
	out := &pantherclawv1.ModelSettings{
		Enabled: s.Enabled, Available: s.Available, KeySet: s.KeySet, Model: s.Model,
		CallsPerMinute: int32(s.CallsPerMinute), TokensPerDay: s.TokensPerDay, //nolint:gosec // bounded by the server's config
		MaxCallsPerMinute: int32(h.svc.Config.CallsPerMinute), MaxTokensPerDay: h.svc.Config.TokensPerDay, //nolint:gosec // bounded by the server's config
	}
	if s.KeySetAt != nil {
		out.KeySetAt = timestamppb.New(*s.KeySetAt)
	}
	return out
}

// GetModelSettings implements ModelServiceHandler.
func (h *Handler) GetModelSettings(ctx context.Context, _ *pantherclawv1.GetModelSettingsRequest) (
	*pantherclawv1.GetModelSettingsResponse, error,
) {
	s, err := h.svc.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetModelSettingsResponse{Settings: h.settings(s)}, nil
}

// UpdateModelSettings implements ModelServiceHandler.
func (h *Handler) UpdateModelSettings(ctx context.Context, r *pantherclawv1.UpdateModelSettingsRequest) (
	*pantherclawv1.UpdateModelSettingsResponse, error,
) {
	s, err := h.svc.SetLimits(ctx, app.Limits{
		Model: r.GetModel(), CallsPerMinute: int(r.GetCallsPerMinute()), TokensPerDay: r.GetTokensPerDay(),
	})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateModelSettingsResponse{Settings: h.settings(s)}, nil
}

// DisableModelDrafting implements ModelServiceHandler.
func (h *Handler) DisableModelDrafting(ctx context.Context, _ *pantherclawv1.DisableModelDraftingRequest) (
	*pantherclawv1.DisableModelDraftingResponse, error,
) {
	s, err := h.svc.Disable(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DisableModelDraftingResponse{Settings: h.settings(s)}, nil
}

// ClearModelKey implements ModelServiceHandler.
func (h *Handler) ClearModelKey(ctx context.Context, _ *pantherclawv1.ClearModelKeyRequest) (
	*pantherclawv1.ClearModelKeyResponse, error,
) {
	s, err := h.svc.ClearKey(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ClearModelKeyResponse{Settings: h.settings(s)}, nil
}

func ambiguities(in []app.Ambiguity) []*pantherclawv1.DraftAmbiguity {
	out := make([]*pantherclawv1.DraftAmbiguity, 0, len(in))
	for _, a := range in {
		out = append(out, &pantherclawv1.DraftAmbiguity{Term: a.Term, ProposedThreshold: a.ProposedThreshold})
	}
	return out
}

// DraftQuery implements ModelServiceHandler. Nothing here runs a query.
func (h *Handler) DraftQuery(ctx context.Context, r *pantherclawv1.DraftQueryRequest) (*pantherclawv1.DraftQueryResponse, error) {
	d, err := h.drafter.DraftQuery(ctx, r.GetText(), r.GetTimezone())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DraftQueryResponse{
		Interpretation: searchrpc.InterpretationProto(d.Interpretation), Ambiguities: ambiguities(d.Thresholds), CallId: d.Call.String(),
	}, nil
}

// DraftAutomation implements ModelServiceHandler. It stores a DRAFT and enables
// nothing.
func (h *Handler) DraftAutomation(ctx context.Context, r *pantherclawv1.DraftAutomationRequest) (*pantherclawv1.DraftAutomationResponse, error) {
	d, err := h.svc.DraftAutomation(ctx, r.GetText())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DraftAutomationResponse{
		AutomationId: d.Automation.String(), VersionId: d.Version.String(), Name: d.Name,
		Ambiguities: ambiguities(d.Ambiguities), CallId: d.Call.String(),
	}, nil
}

// GetModelDraft implements ModelServiceHandler.
func (h *Handler) GetModelDraft(ctx context.Context, r *pantherclawv1.GetModelDraftRequest) (*pantherclawv1.GetModelDraftResponse, error) {
	version, err := ids.ParseUUID(r.GetVersionId())
	if err != nil {
		return nil, app.ErrDraftNotFound
	}
	d, err := h.svc.GetDraft(ctx, version)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetModelDraftResponse{Draft: draftProto(d)}, nil
}

func draftProto(d app.StoredDraft) *pantherclawv1.ModelDraft {
	return &pantherclawv1.ModelDraft{
		VersionId: d.Version.String(), Kind: d.Kind, Origin: d.Origin, Ambiguities: ambiguities(d.Ambiguities),
		CallId: d.Call.String(), CreatedAt: timestamppb.New(d.CreatedAt),
	}
}

// ListModelDrafts implements ModelServiceHandler.
func (h *Handler) ListModelDrafts(ctx context.Context, r *pantherclawv1.ListModelDraftsRequest) (*pantherclawv1.ListModelDraftsResponse, error) {
	pr, err := page.Parse(r.GetPageSize(), r.GetPageToken())
	if err != nil {
		return nil, err
	}
	drafts, next, err := h.svc.ListDrafts(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListModelDraftsResponse{NextPageToken: next}
	for _, d := range drafts {
		out.Drafts = append(out.Drafts, draftProto(d))
	}
	return out, nil
}

// defaultUsageDays is the period GetModelUsage reads when none is named.
const defaultUsageDays = 30

// GetModelUsage implements ModelServiceHandler.
func (h *Handler) GetModelUsage(ctx context.Context, r *pantherclawv1.GetModelUsageRequest) (*pantherclawv1.GetModelUsageResponse, error) {
	days := r.GetDays()
	if days == 0 {
		days = defaultUsageDays
	}
	since := time.Now().UTC().AddDate(0, 0, -int(days))
	rows, err := h.svc.Usage(ctx, since)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetModelUsageResponse{Since: timestamppb.New(since)}
	for _, u := range rows {
		out.Rows = append(out.Rows, &pantherclawv1.ModelUsageRow{
			Task: u.Task, Outcome: u.Outcome, Calls: u.Calls, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
			ReservedTokens: u.ReservedTokens,
		})
	}
	return out, nil
}

// DraftPolicy implements ModelServiceHandler. It stores a DRAFT and publishes
// nothing.
func (h *Handler) DraftPolicy(ctx context.Context, r *pantherclawv1.DraftPolicyRequest) (*pantherclawv1.DraftPolicyResponse, error) {
	d, err := h.svc.DraftPolicy(ctx, r.GetText())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.DraftPolicyResponse{
		VersionId: d.Version.String(), Version: int32(d.Number), Summaries: d.Summaries, //nolint:gosec // a policy's version number
		Ambiguities: ambiguities(d.Ambiguities), CallId: d.Call.String(),
	}, nil
}
