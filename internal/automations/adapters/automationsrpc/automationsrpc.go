// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package automationsrpc serves AutomationService over Connect (G0 M11
// part 2 D5, D7, D28). Handlers only translate: authentication, the coarse
// permission check and protovalidate have run before a handler is called,
// and the use cases check the caller again.
package automationsrpc

import (
	"context"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves AutomationService.
type Handler struct {
	pantherclawv1connect.UnimplementedAutomationServiceHandler
	svc *autoapp.Service
}

// New returns the AutomationService handler.
func New(svc *autoapp.Service) *Handler { return &Handler{svc: svc} }

var errID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "an id is not a UUID")

func parse(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, errID
	}
	return id, nil
}

func parseAll(xs []string) ([]ids.UUID, error) {
	out := make([]ids.UUID, 0, len(xs))
	for _, x := range xs {
		id, err := parse(x)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func idString(id ids.UUID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}

func strs(xs []ids.UUID) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.String())
	}
	return out
}

func ts(t *time.Time) *timestamppb.Timestamp {
	if t == nil || t.IsZero() {
		return nil
	}
	return timestamppb.New(*t)
}

var kinds = map[autodomain.WorkKind]pantherclawv1.AutomationKind{
	autodomain.WorkAgent:    pantherclawv1.AutomationKind_AUTOMATION_KIND_AGENT_WORK,
	autodomain.WorkSecurity: pantherclawv1.AutomationKind_AUTOMATION_KIND_SECURITY_WORK,
}

var states = map[autodomain.State]pantherclawv1.AutomationState{
	autodomain.StateDraft:   pantherclawv1.AutomationState_AUTOMATION_STATE_DRAFT,
	autodomain.StateActive:  pantherclawv1.AutomationState_AUTOMATION_STATE_ACTIVE,
	autodomain.StatePaused:  pantherclawv1.AutomationState_AUTOMATION_STATE_PAUSED,
	autodomain.StateRetired: pantherclawv1.AutomationState_AUTOMATION_STATE_RETIRED,
}

var rollouts = map[autodomain.Rollout]pantherclawv1.AutomationRollout{
	autodomain.RolloutShadow: pantherclawv1.AutomationRollout_AUTOMATION_ROLLOUT_SHADOW,
	autodomain.RolloutCohort: pantherclawv1.AutomationRollout_AUTOMATION_ROLLOUT_COHORT,
	autodomain.RolloutFull:   pantherclawv1.AutomationRollout_AUTOMATION_ROLLOUT_FULL,
}

var versionStates = map[autodomain.VersionState]pantherclawv1.AutomationVersionState{
	autodomain.VersionDraft:      pantherclawv1.AutomationVersionState_AUTOMATION_VERSION_STATE_DRAFT,
	autodomain.VersionValidated:  pantherclawv1.AutomationVersionState_AUTOMATION_VERSION_STATE_VALIDATED,
	autodomain.VersionTested:     pantherclawv1.AutomationVersionState_AUTOMATION_VERSION_STATE_TESTED,
	autodomain.VersionPublished:  pantherclawv1.AutomationVersionState_AUTOMATION_VERSION_STATE_PUBLISHED,
	autodomain.VersionSuperseded: pantherclawv1.AutomationVersionState_AUTOMATION_VERSION_STATE_SUPERSEDED,
	autodomain.VersionRetired:    pantherclawv1.AutomationVersionState_AUTOMATION_VERSION_STATE_RETIRED,
}

var ceilingStates = map[autodomain.CeilingState]pantherclawv1.AutomationCeilingState{
	autodomain.CeilingActive:     pantherclawv1.AutomationCeilingState_AUTOMATION_CEILING_STATE_ACTIVE,
	autodomain.CeilingSuperseded: pantherclawv1.AutomationCeilingState_AUTOMATION_CEILING_STATE_SUPERSEDED,
	autodomain.CeilingExpired:    pantherclawv1.AutomationCeilingState_AUTOMATION_CEILING_STATE_EXPIRED,
	autodomain.CeilingVoid:       pantherclawv1.AutomationCeilingState_AUTOMATION_CEILING_STATE_VOID,
	autodomain.CeilingRevoked:    pantherclawv1.AutomationCeilingState_AUTOMATION_CEILING_STATE_REVOKED,
}

func reverse[K comparable, V comparable](m map[K]V, v V) (K, bool) {
	for k, x := range m {
		if x == v {
			return k, true
		}
	}
	var zero K
	return zero, false
}

// AutomationPB converts an automation.
func AutomationPB(a autoapp.Automation) *pantherclawv1.Automation {
	out := &pantherclawv1.Automation{
		Id: a.ID.String(), Name: a.Name, Purpose: a.Purpose, Kind: kinds[a.Kind], OwnerUserId: a.Owner.String(),
		ServiceAccountId: a.ServiceAccount.String(), State: states[a.State], Rollout: rollouts[a.Rollout],
		CohortAgents: strs(a.CohortAgents), EnabledVersionId: idString(a.EnabledVersion), PauseReason: string(a.PauseReason),
		PausedAt: ts(a.PausedAt), CreatedBy: a.CreatedBy.String(), CreatedAt: ts(&a.CreatedAt), UpdatedAt: ts(&a.UpdatedAt),
		RetiredAt: ts(a.RetiredAt),
	}
	if c := a.Ceiling; c != nil {
		out.Ceiling = &pantherclawv1.AutomationCeiling{
			Id: c.ID.String(), VersionId: c.Version.String(), Digest: c.Digest, ApprovedBy: strs(c.ApprovedBy),
			ChangeRequestId: c.ChangeRequest.String(), State: ceilingStates[c.State], ReviewBy: ts(&c.ReviewBy),
			VoidReason: c.VoidReason, CreatedAt: ts(&c.CreatedAt), EndedAt: ts(c.EndedAt),
		}
	}
	return out
}

// VersionPB converts a version.
func VersionPB(v autoapp.Version) *pantherclawv1.AutomationVersion {
	out := &pantherclawv1.AutomationVersion{
		Id: v.ID.String(), AutomationId: v.Automation.String(), Number: int32(v.Number), State: versionStates[v.State], //nolint:gosec // small
		Definition: string(v.Definition), Digest: v.Digest, Summary: v.Summary, TestedRunId: idString(v.TestedRun),
		CreatedBy: v.CreatedBy.String(), CreatedAt: ts(&v.CreatedAt), ValidatedAt: ts(v.ValidatedAt), TestedAt: ts(v.TestedAt),
		PublishedAt: ts(v.PublishedAt), ChangeRequestId: idString(v.ChangeRequest),
	}
	for _, f := range v.Findings {
		out.Findings = append(out.Findings, &pantherclawv1.AutomationFinding{
			Code: f.Code, Severity: string(f.Severity), Path: f.Path, Message: f.Message, Example: f.Example,
		})
	}
	return out
}

func effectPB(e autoapp.ControlEffect) *pantherclawv1.AutomationControlEffect {
	return &pantherclawv1.AutomationControlEffect{
		GrantsRevoked: strs(e.GrantsRevoked), RunsEnded: strs(e.RunsEnded), LaunchesCancelled: strs(e.LaunchesCancelled),
		DeliveriesCancelled: strs(e.DeliveriesCancelled), ExecutionsAffected: strs(e.ExecutionsAffected),
	}
}

// CreateAutomation implements AutomationServiceHandler.
func (h *Handler) CreateAutomation(ctx context.Context, r *pantherclawv1.CreateAutomationRequest) (*pantherclawv1.CreateAutomationResponse, error) {
	owner, err := parse(r.GetOwnerUserId())
	if err != nil {
		return nil, err
	}
	kind, _ := reverse(kinds, r.GetKind())
	a, err := h.svc.CreateAutomation(ctx, r.GetName(), r.GetPurpose(), kind, owner)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateAutomationResponse{Automation: AutomationPB(a)}, nil
}

// GetAutomation implements AutomationServiceHandler.
func (h *Handler) GetAutomation(ctx context.Context, r *pantherclawv1.GetAutomationRequest) (*pantherclawv1.GetAutomationResponse, error) {
	id, err := parse(r.GetId())
	if err != nil {
		return nil, err
	}
	a, err := h.svc.GetAutomation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetAutomationResponse{Automation: AutomationPB(a)}, nil
}

// ListAutomations implements AutomationServiceHandler. The page token is
// the last name of the previous page.
func (h *Handler) ListAutomations(ctx context.Context, r *pantherclawv1.ListAutomationsRequest) (*pantherclawv1.ListAutomationsResponse, error) {
	limit := int(r.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	var ss []autodomain.State
	for _, s := range r.GetStates() {
		if x, ok := reverse(states, s); ok {
			ss = append(ss, x)
		}
	}
	as, err := h.svc.ListAutomations(ctx, ss, r.GetPageToken(), limit)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListAutomationsResponse{}
	for _, a := range as {
		out.Automations = append(out.Automations, AutomationPB(a))
	}
	if len(as) == limit {
		out.NextPageToken = as[len(as)-1].Name
	}
	return out, nil
}

// CreateDraftVersion implements AutomationServiceHandler.
func (h *Handler) CreateDraftVersion(ctx context.Context, r *pantherclawv1.CreateDraftVersionRequest) (*pantherclawv1.CreateDraftVersionResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	v, err := h.svc.CreateDraftVersion(ctx, id, []byte(r.GetDefinition()))
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CreateDraftVersionResponse{Version: VersionPB(v)}, nil
}

// UpdateDraftVersion implements AutomationServiceHandler.
func (h *Handler) UpdateDraftVersion(ctx context.Context, r *pantherclawv1.UpdateDraftVersionRequest) (*pantherclawv1.UpdateDraftVersionResponse, error) {
	id, err := parse(r.GetVersionId())
	if err != nil {
		return nil, err
	}
	v, err := h.svc.UpdateDraftVersion(ctx, id, []byte(r.GetDefinition()), r.GetBaseDigest())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.UpdateDraftVersionResponse{Version: VersionPB(v)}, nil
}

// ValidateVersion implements AutomationServiceHandler.
func (h *Handler) ValidateVersion(ctx context.Context, r *pantherclawv1.ValidateVersionRequest) (*pantherclawv1.ValidateVersionResponse, error) {
	id, err := parse(r.GetVersionId())
	if err != nil {
		return nil, err
	}
	v, ok, err := h.svc.ValidateVersion(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ValidateVersionResponse{Version: VersionPB(v), Valid: ok}, nil
}

// GetVersion implements AutomationServiceHandler.
func (h *Handler) GetVersion(ctx context.Context, r *pantherclawv1.GetVersionRequest) (*pantherclawv1.GetVersionResponse, error) {
	id, err := parse(r.GetVersionId())
	if err != nil {
		return nil, err
	}
	v, err := h.svc.GetVersion(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetVersionResponse{Version: VersionPB(v)}, nil
}

// ListVersions implements AutomationServiceHandler. The page token is the
// last version number of the previous page.
func (h *Handler) ListVersions(ctx context.Context, r *pantherclawv1.ListVersionsRequest) (*pantherclawv1.ListVersionsResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	limit := int(r.GetPageSize())
	if limit == 0 {
		limit = 50
	}
	before := 0
	if t := r.GetPageToken(); t != "" {
		if before, err = strconv.Atoi(t); err != nil {
			return nil, pcerr.New(pcerr.InvalidArgument, "INVALID_PAGE_TOKEN", "the page token is not valid")
		}
	}
	vs, err := h.svc.ListVersions(ctx, id, before, limit)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListVersionsResponse{}
	for _, v := range vs {
		out.Versions = append(out.Versions, VersionPB(v))
	}
	if len(vs) == limit {
		out.NextPageToken = strconv.Itoa(vs[len(vs)-1].Number)
	}
	return out, nil
}

// GetVersionGraph implements AutomationServiceHandler.
func (h *Handler) GetVersionGraph(ctx context.Context, r *pantherclawv1.GetVersionGraphRequest) (*pantherclawv1.GetVersionGraphResponse, error) {
	id, err := parse(r.GetVersionId())
	if err != nil {
		return nil, err
	}
	nodes, edges, err := h.svc.GetVersionGraph(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetVersionGraphResponse{}
	for _, n := range nodes {
		out.Nodes = append(out.Nodes, &pantherclawv1.AutomationGraphNode{
			Id: n.ID, Type: n.Type, Kind: n.Kind, Label: n.Label, Authority: n.Authority, Effectful: n.Effectful,
		})
	}
	for _, e := range edges {
		out.Edges = append(out.Edges, &pantherclawv1.AutomationGraphEdge{From: e.From, To: e.To, Type: e.Type})
	}
	return out, nil
}

// RequestEnable implements AutomationServiceHandler.
func (h *Handler) RequestEnable(ctx context.Context, r *pantherclawv1.RequestEnableRequest) (*pantherclawv1.RequestEnableResponse, error) {
	id, err := parse(r.GetVersionId())
	if err != nil {
		return nil, err
	}
	cohort, err := parseAll(r.GetCohortAgents())
	if err != nil {
		return nil, err
	}
	var cohortID ids.UUID
	if r.CohortId != nil {
		if cohortID, err = parse(r.GetCohortId()); err != nil {
			return nil, err
		}
	}
	rollout, _ := reverse(rollouts, r.GetRollout())
	e, err := h.svc.RequestEnable(ctx, id, rollout, cohort, cohortID)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RequestEnableResponse{
		ChangeRequestId: e.Request.ID.String(), Required: int32(e.Required), ExpiresAt: ts(&e.Request.ExpiresAt), //nolint:gosec // 1..2
	}, nil
}

// NarrowRollout implements AutomationServiceHandler.
func (h *Handler) NarrowRollout(ctx context.Context, r *pantherclawv1.NarrowRolloutRequest) (*pantherclawv1.NarrowRolloutResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	cohort, err := parseAll(r.GetCohortAgents())
	if err != nil {
		return nil, err
	}
	rollout, _ := reverse(rollouts, r.GetRollout())
	a, err := h.svc.NarrowRollout(ctx, id, rollout, cohort)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.NarrowRolloutResponse{Automation: AutomationPB(a)}, nil
}

// PauseAutomation implements AutomationServiceHandler.
func (h *Handler) PauseAutomation(ctx context.Context, r *pantherclawv1.PauseAutomationRequest) (*pantherclawv1.PauseAutomationResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	a, e, err := h.svc.PauseAutomation(ctx, id, r.GetCancelActive(), r.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.PauseAutomationResponse{Automation: AutomationPB(a), Effect: effectPB(e)}, nil
}

// ResumeAutomation implements AutomationServiceHandler.
func (h *Handler) ResumeAutomation(ctx context.Context, r *pantherclawv1.ResumeAutomationRequest) (*pantherclawv1.ResumeAutomationResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	a, n, err := h.svc.ResumeAutomation(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ResumeAutomationResponse{Automation: AutomationPB(a), Replayed: int32(n)}, nil //nolint:gosec // small
}

// RetireAutomation implements AutomationServiceHandler.
func (h *Handler) RetireAutomation(ctx context.Context, r *pantherclawv1.RetireAutomationRequest) (*pantherclawv1.RetireAutomationResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	a, e, err := h.svc.RetireAutomation(ctx, id, r.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RetireAutomationResponse{Automation: AutomationPB(a), Effect: effectPB(e)}, nil
}

// RevokeAuthority implements AutomationServiceHandler.
func (h *Handler) RevokeAuthority(ctx context.Context, r *pantherclawv1.RevokeAuthorityRequest) (*pantherclawv1.RevokeAuthorityResponse, error) {
	id, err := parse(r.GetAutomationId())
	if err != nil {
		return nil, err
	}
	a, e, err := h.svc.RevokeAuthority(ctx, id, r.GetReason())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RevokeAuthorityResponse{Automation: AutomationPB(a), Effect: effectPB(e)}, nil
}

// IdentityPB converts an inventory row (agents.proto ListAgents, D15).
func IdentityPB(x autoapp.Identity) *pantherclawv1.AutomationIdentity {
	return &pantherclawv1.AutomationIdentity{
		AutomationId: x.Automation.String(), ServiceAccountId: x.ServiceAccount.String(), Name: x.Name,
		OwnerUserId: x.Owner.String(), State: states[x.State], Rollout: rollouts[x.Rollout],
		EnabledVersionId: idString(x.EnabledVersion), CeilingAgents: int32(x.CeilingAgents), //nolint:gosec // ≤ 50
		ActiveGrants: int32(x.ActiveGrants), ReviewBy: ts(x.ReviewBy), //nolint:gosec // bounded
	}
}
