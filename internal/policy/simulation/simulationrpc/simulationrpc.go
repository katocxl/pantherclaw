// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package simulationrpc serves PolicySimulationService over Connect (G0
// M11.1 D15). Handlers only translate: authentication, the coarse
// permission check and protovalidate have run before a handler is called,
// and the use cases check policy.simulate and the edition.
package simulationrpc

import (
	"cmp"
	"context"
	"encoding/hex"
	"maps"
	"slices"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
)

// Handler serves PolicySimulationService.
type Handler struct {
	pantherclawv1connect.UnimplementedPolicySimulationServiceHandler
	svc *simulation.Service
}

// New returns the PolicySimulationService handler.
func New(svc *simulation.Service) *Handler { return &Handler{svc: svc} }

var states = map[simulation.State]pantherclawv1.PolicySimulationState{
	simulation.Queued:    pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_QUEUED,
	simulation.Running:   pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_RUNNING,
	simulation.Done:      pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_DONE,
	simulation.Failed:    pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_FAILED,
	simulation.Cancelled: pantherclawv1.PolicySimulationState_POLICY_SIMULATION_STATE_CANCELLED,
}

var categories = map[replay.Category]pantherclawv1.PolicySimulationCategory{
	replay.Unchanged:        pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_UNCHANGED,
	replay.NewlyDenied:      pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_DENIED,
	replay.NewlyHeld:        pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_HELD,
	replay.NewlyConstrained: pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_CONSTRAINED,
	replay.NewlyAllowed:     pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_NEWLY_ALLOWED,
	replay.ReasonChanged:    pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_REASON_CHANGED,
	replay.Unevaluable:      pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_UNEVALUABLE,
}

func countsPB(c simulation.Counts) *pantherclawv1.PolicySimulationCounts {
	return &pantherclawv1.PolicySimulationCounts{
		Unchanged: n(c[replay.Unchanged]), NewlyDenied: n(c[replay.NewlyDenied]), NewlyHeld: n(c[replay.NewlyHeld]),
		NewlyConstrained: n(c[replay.NewlyConstrained]), NewlyAllowed: n(c[replay.NewlyAllowed]),
		ReasonChanged: n(c[replay.ReasonChanged]), Unevaluable: n(c[replay.Unevaluable]),
	}
}

func n(v int) int32 { return int32(min(v, simulation.MaxEvaluations)) } //nolint:gosec // G115: bounded

func groupsPB(g map[string]simulation.Counts) []*pantherclawv1.PolicySimulationGroup {
	out := make([]*pantherclawv1.PolicySimulationGroup, 0, len(g))
	for _, k := range slices.Sorted(maps.Keys(g)) {
		out = append(out, &pantherclawv1.PolicySimulationGroup{Key: k, Counts: countsPB(g[k])})
	}
	// Most changed first, then by key.
	slices.SortStableFunc(out, func(a, b *pantherclawv1.PolicySimulationGroup) int {
		return cmp.Compare(changed(b.GetCounts()), changed(a.GetCounts()))
	})
	return out
}

func changed(c *pantherclawv1.PolicySimulationCounts) int32 {
	return c.GetNewlyDenied() + c.GetNewlyHeld() + c.GetNewlyConstrained() + c.GetNewlyAllowed() + c.GetReasonChanged()
}

func simulationPB(s simulation.Simulation) *pantherclawv1.PolicySimulation {
	out := &pantherclawv1.PolicySimulation{
		Id: s.ID.String(), VersionId: s.Version.String(), ContentDigest: hex.EncodeToString(s.ContentDigest[:]),
		WindowStart: timestamppb.New(s.WindowStart), WindowEnd: timestamppb.New(s.WindowEnd), MaxEvaluations: n(s.Max),
		State: states[s.State], Evaluated: n(s.Evaluated), Counts: countsPB(s.Report.Counts),
		ByOperation: groupsPB(s.Report.ByOperation), ByAgent: groupsPB(s.Report.ByAgent),
		Notices: s.Notices(), Limits: simulation.Limits, RequestedBy: s.RequestedBy, CreateTime: timestamppb.New(s.Created),
		Error: s.Error,
	}
	for _, d := range slices.Sorted(maps.Keys(s.Report.HeldPerDay)) {
		out.NewlyHeldPerDay = append(out.NewlyHeldPerDay, &pantherclawv1.PolicySimulationDay{Day: d, NewlyHeld: n(s.Report.HeldPerDay[d])})
	}
	for _, r := range slices.Sorted(maps.Keys(s.Report.HeldByRole)) {
		out.NewlyHeldByRole = append(out.NewlyHeldByRole, &pantherclawv1.PolicySimulationRole{Role: r, NewlyHeld: n(s.Report.HeldByRole[r])})
	}
	if s.Started != nil {
		out.StartTime = timestamppb.New(*s.Started)
	}
	if s.Finished != nil {
		out.FinishTime = timestamppb.New(*s.Finished)
	}
	return out
}

func parseID(s string) (ids.UUID, error) {
	id, err := ids.ParseUUID(s)
	if err != nil {
		return ids.UUID{}, simulation.ErrNotFound
	}
	return id, nil
}

// SimulatePolicyVersion implements PolicySimulationServiceHandler.
func (h *Handler) SimulatePolicyVersion(ctx context.Context, r *pantherclawv1.SimulatePolicyVersionRequest) (*pantherclawv1.SimulatePolicyVersionResponse, error) {
	v, err := ids.ParseUUID(r.GetVersionId())
	if err != nil {
		return nil, simulation.ErrVersionNotFound
	}
	s, err := h.svc.Simulate(ctx, simulation.Request{Version: v, Days: int(r.GetDays()), Max: int(r.GetMaxEvaluations())})
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.SimulatePolicyVersionResponse{Simulation: simulationPB(s)}, nil
}

// GetSimulation implements PolicySimulationServiceHandler.
func (h *Handler) GetSimulation(ctx context.Context, r *pantherclawv1.GetSimulationRequest) (*pantherclawv1.GetSimulationResponse, error) {
	id, err := parseID(r.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetSimulationResponse{Simulation: simulationPB(s)}, nil
}

// ListSimulations implements PolicySimulationServiceHandler.
func (h *Handler) ListSimulations(ctx context.Context, r *pantherclawv1.ListSimulationsRequest) (*pantherclawv1.ListSimulationsResponse, error) {
	pr, err := page.Parse(r.GetPageSize(), r.GetPageToken())
	if err != nil {
		return nil, err
	}
	p, err := h.svc.List(ctx, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSimulationsResponse{NextPageToken: p.Next}
	for _, s := range p.Items {
		out.Simulations = append(out.Simulations, simulationPB(s))
	}
	return out, nil
}

// CancelSimulation implements PolicySimulationServiceHandler.
func (h *Handler) CancelSimulation(ctx context.Context, r *pantherclawv1.CancelSimulationRequest) (*pantherclawv1.CancelSimulationResponse, error) {
	id, err := parseID(r.GetId())
	if err != nil {
		return nil, err
	}
	s, err := h.svc.Cancel(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.CancelSimulationResponse{Simulation: simulationPB(s)}, nil
}

// ListSimulationSamples implements PolicySimulationServiceHandler.
func (h *Handler) ListSimulationSamples(ctx context.Context, r *pantherclawv1.ListSimulationSamplesRequest) (*pantherclawv1.ListSimulationSamplesResponse, error) {
	id, err := parseID(r.GetSimulationId())
	if err != nil {
		return nil, err
	}
	f := simulation.SampleFilter{Operation: r.GetOperation()}
	if c := r.GetCategory(); c != pantherclawv1.PolicySimulationCategory_POLICY_SIMULATION_CATEGORY_UNSPECIFIED {
		for k, v := range categories {
			if v == c {
				f.Category = k
			}
		}
	}
	p, err := h.svc.Samples(ctx, id, f, r.GetPageSize(), r.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListSimulationSamplesResponse{NextPageToken: p.Next}
	for _, s := range p.Items {
		out.Samples = append(out.Samples, &pantherclawv1.PolicySimulationSample{
			Category: categories[s.Category], TransactionId: s.Transaction.String(), Evaluation: int32(s.Evaluation), //nolint:gosec // 1..64
			AgentId: s.Agent.String(), Operation: s.Operation, OriginalDecision: s.Original, OriginalReason: s.OrigReason,
			ProposedDecision: s.Proposed, ProposedReason: s.PropReason, Limitations: s.Limitations,
		})
	}
	return out, nil
}
