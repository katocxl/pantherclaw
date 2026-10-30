// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package assurancerpc serves AssuranceService over Connect (G0 M11 part 2
// D34–D38, D59). Handlers only translate: authentication, the coarse
// permission check and protovalidate have run before a handler is called,
// and the use cases check the permission at the org, exposure.read per
// agent and the edition.
package assurancerpc

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Handler serves AssuranceService.
type Handler struct {
	pantherclawv1connect.UnimplementedAssuranceServiceHandler
	svc *assurance.Service
}

// New returns the handler.
func New(svc *assurance.Service) *Handler { return &Handler{svc: svc} }

// id reads a uuid protovalidate already checked.
func id(s string) ids.UUID {
	u, _ := ids.ParseUUID(s)
	return u
}

func str(u *ids.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

func caseOf(c *pb.AutomationTestCase) assurance.Case {
	out := assurance.Case{
		Name: c.GetName(), Kind: assurance.CaseKind(c.GetKind()), Trigger: assurance.CaseTrigger{Params: c.GetParams()},
		Expect: assurance.Expect{State: c.GetExpect().GetState(), Reason: c.GetExpect().GetReason(), Steps: c.GetExpect().GetSteps()},
	}
	for _, s := range c.GetStubs() {
		if out.Stubs == nil {
			out.Stubs = map[string][]assurance.StubResult{}
		}
		for _, r := range s.GetResults() {
			out.Stubs[s.GetStepId()] = append(out.Stubs[s.GetStepId()], assurance.StubResult{
				State: r.GetState(), Effect: r.GetEffect(), Reason: r.GetReason(), Output: r.GetOutput(), Evidence: r.GetEvidence(),
				Wait: autodomain.Duration(r.GetWait().AsDuration()),
			})
		}
	}
	return out
}

func casePB(c assurance.Case) *pb.AutomationTestCase {
	out := &pb.AutomationTestCase{
		Name: c.Name, Kind: string(c.Kind), Params: c.Trigger.Params,
		Expect: &pb.AutomationTestExpectation{State: c.Expect.State, Reason: c.Expect.Reason, Steps: c.Expect.Steps},
	}
	for _, step := range slices.Sorted(maps.Keys(c.Stubs)) {
		s := &pb.AutomationStepStub{StepId: step}
		for _, r := range c.Stubs[step] {
			x := &pb.AutomationStubResult{State: r.State, Effect: r.Effect, Reason: r.Reason, Output: r.Output, Evidence: r.Evidence}
			if r.Wait != 0 {
				x.Wait = durationpb.New(r.Wait.D())
			}
			s.Results = append(s.Results, x)
		}
		out.Stubs = append(out.Stubs, s)
	}
	return out
}

// SetTestCases implements AssuranceServiceHandler.
func (h *Handler) SetTestCases(ctx context.Context, req *pb.SetTestCasesRequest) (*pb.SetTestCasesResponse, error) {
	cases := make([]assurance.Case, 0, len(req.GetCases()))
	for _, c := range req.GetCases() {
		cases = append(cases, caseOf(c))
	}
	missing, err := h.svc.SetTestCases(ctx, id(req.GetVersionId()), cases)
	if err != nil {
		return nil, err
	}
	return &pb.SetTestCasesResponse{MissingKinds: missing}, nil
}

// ListTestCases implements AssuranceServiceHandler.
func (h *Handler) ListTestCases(ctx context.Context, req *pb.ListTestCasesRequest) (*pb.ListTestCasesResponse, error) {
	cases, missing, err := h.svc.ListTestCases(ctx, id(req.GetVersionId()))
	if err != nil {
		return nil, err
	}
	out := &pb.ListTestCasesResponse{MissingKinds: missing}
	for _, c := range cases {
		out.Cases = append(out.Cases, casePB(c))
	}
	return out, nil
}

// InspectVersion implements AssuranceServiceHandler.
func (h *Handler) InspectVersion(ctx context.Context, req *pb.InspectVersionRequest) (*pb.InspectVersionResponse, error) {
	in, err := h.svc.InspectVersion(ctx, id(req.GetVersionId()))
	if err != nil {
		return nil, err
	}
	return inspection(in), nil
}

func inspection(in assurance.Inspection) *pb.InspectVersionResponse {
	out := &pb.InspectVersionResponse{Notes: in.Notes}
	for _, p := range in.Paths {
		out.Paths = append(out.Paths, &pb.InspectedPath{NodeIds: p.Nodes, Outcome: p.Outcome})
	}
	for _, s := range in.Steps {
		x := &pb.InspectedStep{StepId: s.ID, Kind: s.Kind, Effectful: s.Effectful, Scopes: s.Scopes}
		for _, o := range s.Operations {
			x.Operations = append(x.Operations, &pb.InspectedOperation{
				Operation: o.Operation, EffectKinds: o.EffectKinds, Reversibility: o.Reversibility, Consequences: o.Consequences,
				Coverage: o.Coverage, Approvals: o.Approvals, Verification: o.Verification,
			})
		}
		out.Steps = append(out.Steps, x)
	}
	return out
}

func simStep(st assurance.SimStep) *pb.SimulationStep {
	return &pb.SimulationStep{StepId: st.ID, Kind: st.Kind, Decision: st.Decision, Reason: st.Reason, Branch: st.Branch}
}

func reachPB(r assurance.Reach) *pb.BlastRadiusReach {
	return &pb.BlastRadiusReach{
		ResourceGroup: r.ResourceGroup, Verb: string(r.Verb), Operation: r.Operation, ConnectionId: str(r.Connection),
		AgentId: str(r.Agent), Irreversible: r.Irreversible, Coverage: string(r.Coverage),
	}
}

// count converts a bounded count.
func count(n int) int32 { return int32(min(n, 1<<30)) } //nolint:gosec // G115: bounded

// PreviewBlastRadius implements AssuranceServiceHandler.
func (h *Handler) PreviewBlastRadius(ctx context.Context, req *pb.PreviewBlastRadiusRequest) (*pb.PreviewBlastRadiusResponse, error) {
	b, err := h.svc.PreviewBlastRadius(ctx, id(req.GetVersionId()))
	if err != nil {
		return nil, err
	}
	out := &pb.PreviewBlastRadiusResponse{
		ConsequentialOperations: b.Consequential, MaxGrantsPerDay: count(b.MaxGrants), MaxRunsPerDay: count(b.MaxRuns),
		MaxConcurrency: count(b.MaxConcurrency), DelegationDepth: count(b.DelegationDepth),
		DelegationMaxChildren: count(b.DelegationChildren), Approvals: b.Approvals, Restrictions: b.Restrictions,
		UncoveredRoutes: b.Uncovered, UncertainSideEffects: b.UncertainEffects, Restricted: b.Restricted, Notes: b.Notes,
	}
	for _, r := range b.Reach {
		out.Reach = append(out.Reach, reachPB(r))
	}
	for _, m := range b.MaxSpend {
		out.MaxSpendPerDay = append(out.MaxSpendPerDay, &pb.SimulationBudget{Currency: m.Currency, MaxPerDay: m.MaxPerDay})
	}
	for _, s := range b.Shared {
		x := &pb.SharedCredential{ConnectionId: s.Connection.String(), Operations: s.Operations}
		for _, a := range s.Others {
			x.OtherAgentIds = append(x.OtherAgentIds, a.String())
		}
		out.SharedCredentials = append(out.SharedCredentials, x)
	}
	for _, a := range b.TriggeredAutomations {
		out.TriggeredAutomationIds = append(out.TriggeredAutomationIds, a.String())
	}
	return out, nil
}

// CompareRestriction implements AssuranceServiceHandler.
func (h *Handler) CompareRestriction(ctx context.Context, req *pb.CompareRestrictionRequest) (*pb.CompareRestrictionResponse, error) {
	c, err := h.svc.CompareRestriction(ctx, id(req.GetVersionId()), req.GetNarrowedCeiling())
	if err != nil {
		return nil, err
	}
	out := &pb.CompareRestrictionResponse{
		BeforeRights: count(c.Before), AfterRights: count(c.After), Truncated: c.Truncated, Restricted: c.Restricted,
	}
	for _, r := range c.Removed {
		out.Removed = append(out.Removed, reachPB(r))
	}
	for _, x := range c.Failing {
		out.FailingExecutionIds = append(out.FailingExecutionIds, x.String())
	}
	return out, nil
}

func runPB(r assurance.TestRun) *pb.AutomationTestRun {
	out := &pb.AutomationTestRun{
		Id: r.ID.String(), VersionId: r.Version.String(), DefinitionDigest: r.DefinitionDigest, TestsDigest: r.TestsDigest,
		Passed: r.Passed, MissingKinds: r.Result.Missing, RunBy: r.RunBy.String(), CreateTime: timestamppb.New(r.CreatedAt),
	}
	for _, c := range r.Result.Cases {
		out.Cases = append(out.Cases, &pb.AutomationCaseResult{
			Name: c.Name, Kind: string(c.Kind), Passed: c.Passed, State: c.State, Reason: c.Reason, Steps: c.Steps,
			Differences: c.Differences, DuplicateRefused: c.DuplicateRefused, Elapsed: durationpb.New(c.Elapsed.D()),
		})
	}
	return out
}

// RunTests implements AssuranceServiceHandler.
func (h *Handler) RunTests(ctx context.Context, req *pb.RunTestsRequest) (*pb.RunTestsResponse, error) {
	r, err := h.svc.RunTests(ctx, id(req.GetVersionId()))
	if err != nil {
		return nil, err
	}
	return &pb.RunTestsResponse{Run: runPB(r), VersionState: r.VersionState}, nil
}

// GetTestRun implements AssuranceServiceHandler.
func (h *Handler) GetTestRun(ctx context.Context, req *pb.GetTestRunRequest) (*pb.GetTestRunResponse, error) {
	r, err := h.svc.GetTestRun(ctx, id(req.GetId()))
	if err != nil {
		return nil, err
	}
	return &pb.GetTestRunResponse{Run: runPB(r)}, nil
}

// StartAutomationSimulation implements AssuranceServiceHandler.
func (h *Handler) StartAutomationSimulation(ctx context.Context, req *pb.StartAutomationSimulationRequest) (*pb.StartAutomationSimulationResponse, error) {
	sim, err := h.svc.StartSimulation(ctx, id(req.GetVersionId()), req.GetStartTime().AsTime(), req.GetEndTime().AsTime())
	if err != nil {
		return nil, err
	}
	return &pb.StartAutomationSimulationResponse{SimulationId: sim.String()}, nil
}

// GetAutomationSimulation implements AssuranceServiceHandler.
func (h *Handler) GetAutomationSimulation(ctx context.Context, req *pb.GetAutomationSimulationRequest) (*pb.GetAutomationSimulationResponse, error) {
	s, err := h.svc.GetSimulation(ctx, id(req.GetId()))
	if err != nil {
		return nil, err
	}
	out := &pb.AutomationSimulation{
		Id: s.ID.String(), VersionId: s.Version.String(), StartTime: timestamppb.New(s.From), EndTime: timestamppb.New(s.To),
		State: s.State, Error: s.Error, CreateTime: timestamppb.New(s.CreatedAt),
	}
	if s.FinishedAt != nil {
		out.FinishTime = timestamppb.New(*s.FinishedAt)
	}
	if r := s.Results; r != nil {
		for _, d := range r.Days {
			out.Days = append(out.Days, &pb.SimulationDay{Day: d.Day, WouldFire: count(d.WouldFire), Unevaluable: count(d.Unevaluable)})
		}
		for _, x := range r.Samples {
			sample := &pb.SimulationSample{OccurTime: timestamppb.New(x.At), TriggerKind: x.Kind, SourceRef: x.SourceRef, AgentIds: x.Agents}
			for _, st := range x.Steps {
				sample.Steps = append(sample.Steps, simStep(st))
			}
			out.Samples = append(out.Samples, sample)
		}
		for _, k := range slices.Sorted(maps.Keys(r.Missing)) {
			out.MissingContext = append(out.MissingContext, k+"="+strconv.Itoa(r.Missing[k]))
		}
		f := &pb.SimulationForecast{
			ExecutionsPerDay: r.Forecast.ExecutionsPerDay, GatesPerDay: r.Forecast.GatesPerDay,
			EligibleApprovers: count(r.Forecast.EligibleApprovers), GrantsPerDay: r.Forecast.GrantsPerDay,
		}
		for _, b := range r.Forecast.Budget {
			f.Budget = append(f.Budget, &pb.SimulationBudget{Currency: b.Currency, MaxPerDay: b.Max, ExpectedPerDay: b.Expected})
		}
		out.Forecast = f
		out.SamplesHidden = count(r.SamplesHidden)
		out.Notes = r.Notes
		for _, k := range slices.Sorted(maps.Keys(r.LaunchPreview)) {
			out.LaunchPreview = append(out.LaunchPreview, k+"="+r.LaunchPreview[k])
		}
	}
	return &pb.GetAutomationSimulationResponse{Simulation: out}, nil
}

// GetRolloutReport implements AssuranceServiceHandler.
func (h *Handler) GetRolloutReport(ctx context.Context, req *pb.GetRolloutReportRequest) (*pb.GetRolloutReportResponse, error) {
	r, err := h.svc.GetRolloutReport(ctx, id(req.GetAutomationId()))
	if err != nil {
		return nil, err
	}
	out := &pb.GetRolloutReportResponse{
		Stage: r.Stage, VersionId: str(r.Version), ShadowedEffects: count(r.ShadowedEffects), FullVerified: r.FullVerified,
		UnverifiedReasons: r.Unverified, Executions: map[string]int32{}, WouldBeRefusals: map[string]int32{},
	}
	for k, v := range r.Executions {
		out.Executions[k] = count(v)
	}
	for k, v := range r.WouldBeRefusals {
		out.WouldBeRefusals[k] = count(v)
	}
	return out, nil
}

func tsOf(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

// GetAutomationStatus implements AssuranceServiceHandler.
func (h *Handler) GetAutomationStatus(ctx context.Context, req *pb.GetAutomationStatusRequest) (*pb.GetAutomationStatusResponse, error) {
	s, err := h.svc.GetAutomationStatus(ctx, id(req.GetAutomationId()))
	if err != nil {
		return nil, err
	}
	out := &pb.GetAutomationStatusResponse{
		State: s.State, Rollout: s.Rollout, NextRunTime: tsOf(s.NextRun), LatestExecutionId: str(s.LatestExecution),
		LatestState: s.LatestState, LatestEvidenced: s.LatestEvidenced, LatestEndTime: tsOf(s.LatestEnded),
		QueuedTriggers: count(s.Queued), WaitingExecutions: count(s.Waiting), PendingGates: count(s.PendingGates),
		ReviewBy: tsOf(s.ReviewBy),
	}
	for _, b := range s.Budgets {
		out.Budgets = append(out.Budgets, &pb.AutomationBudget{Name: b.Name, Limit: b.Limit, Used: b.Used})
	}
	return out, nil
}

// GetAutomationMetrics implements AssuranceServiceHandler.
func (h *Handler) GetAutomationMetrics(ctx context.Context, req *pb.GetAutomationMetricsRequest) (*pb.GetAutomationMetricsResponse, error) {
	var auto *ids.UUID
	if req.GetAutomationId() != "" {
		a := id(req.GetAutomationId())
		auto = &a
	}
	hours, err := h.svc.GetAutomationMetrics(ctx, auto, req.GetStartTime().AsTime(), req.GetEndTime().AsTime())
	if err != nil {
		return nil, err
	}
	out := &pb.GetAutomationMetricsResponse{}
	for _, o := range hours {
		out.Hours = append(out.Hours, &pb.AutomationOutcomes{
			BucketTime: timestamppb.New(o.Bucket), CompletedWithEvidence: count(o.Completed), Partial: count(o.Partial),
			Failed: count(o.Failed), NeedsReconciliation: count(o.Reconcile), Interventions: count(o.Interventions),
			TriggersRefused: count(o.Refused),
		})
	}
	return out, nil
}
