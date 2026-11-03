// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rangerpc serves RangeService over Connect (G0 M12 W5). Handlers
// only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases
// check the caller's permission over each range agent.
package rangerpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	capp "github.com/katocxl/pantherclaw/internal/campaigns/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
)

// Handler serves RangeService.
type Handler struct {
	pantherclawv1connect.UnimplementedRangeServiceHandler
	svc *app.Service
	// campaigns serves the campaign procedures; nil answers Unavailable.
	campaigns *capp.Service
}

// New returns the RangeService handler.
func New(svc *app.Service) *Handler { return &Handler{svc: svc} }

// StartRange implements RangeServiceHandler.
func (h *Handler) StartRange(ctx context.Context, r *pantherclawv1.StartRangeRequest) (*pantherclawv1.StartRangeResponse, error) {
	agent, err := ids.ParseUUID(r.GetRangeAgentId())
	if err != nil {
		return nil, app.ErrAgentMissing
	}
	in := app.StartInput{Agent: agent, RunnerVersion: r.GetRunnerVersion()}
	for _, s := range r.GetScenarios() {
		in.Scenarios = append(in.Scenarios, domain.Scenario{
			ID: s.GetId(), Digest: s.GetDigest(), Tier: s.GetTier(), Category: s.GetCategory(), Suite: s.GetSuite(), Title: s.GetTitle(), StepCount: int(s.GetStepCount()),
		})
	}
	if r.GetBaselineRangeId() != "" {
		b, err := ids.ParseUUID(r.GetBaselineRangeId())
		if err != nil {
			return nil, app.ErrBaseline
		}
		in.Baseline = &b
	}
	rng, err := h.svc.StartRange(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartRangeResponse{RangeId: rng.ID.String(), StartTime: timestamppb.New(rng.Started)}, nil
}

func expectOf(e *pantherclawv1.RangeExpect) domain.Expect {
	return domain.Expect{Outcome: e.GetOutcome(), Reason: e.GetReason(), Code: e.GetCode()}
}

func optID(s string) (*ids.UUID, error) {
	if s == "" {
		return nil, nil
	}
	id, err := ids.ParseUUID(s)
	if err != nil {
		return nil, app.ErrRecord
	}
	return &id, nil
}

var verdicts = map[pantherclawv1.RangeVerdict]domain.Verdict{
	pantherclawv1.RangeVerdict_RANGE_VERDICT_PASS:    domain.Pass,
	pantherclawv1.RangeVerdict_RANGE_VERDICT_FAIL:    domain.Fail,
	pantherclawv1.RangeVerdict_RANGE_VERDICT_ERROR:   domain.Errored,
	pantherclawv1.RangeVerdict_RANGE_VERDICT_SKIPPED: domain.Skipped,
	pantherclawv1.RangeVerdict_RANGE_VERDICT_MISSING: domain.Missing,
}

func verdictPB(v domain.Verdict) pantherclawv1.RangeVerdict {
	for pb, d := range verdicts {
		if d == v {
			return pb
		}
	}
	return pantherclawv1.RangeVerdict_RANGE_VERDICT_UNSPECIFIED
}

// RecordResult implements RangeServiceHandler.
func (h *Handler) RecordResult(ctx context.Context, r *pantherclawv1.RecordResultRequest) (*pantherclawv1.RecordResultResponse, error) {
	rng, err := ids.ParseUUID(r.GetRangeId())
	if err != nil {
		return nil, app.ErrNotFound
	}
	in := app.RecordInput{Range: rng, Scenario: r.GetScenarioId(), Digest: r.GetScenarioDigest(), Verdict: verdicts[r.GetVerdict()]}
	for _, s := range r.GetSteps() {
		st := domain.StepInput{
			ID: s.GetStepId(), Expect: expectOf(s.GetExpect()), Observed: expectOf(s.GetObserved()), Decisive: s.GetDecisiveControl(),
			Kind: s.GetKind(), ProbeKind: s.GetProbeKind(),
		}
		if st.Transaction, err = optID(s.GetTransactionId()); err != nil {
			return nil, err
		}
		if st.Probe, err = optID(s.GetProbeReportId()); err != nil {
			return nil, err
		}
		in.Steps = append(in.Steps, st)
	}
	res, err := h.svc.RecordResult(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.RecordResultResponse{Result: resultPB(res)}, nil
}

// FinishRange implements RangeServiceHandler.
func (h *Handler) FinishRange(ctx context.Context, r *pantherclawv1.FinishRangeRequest) (*pantherclawv1.FinishRangeResponse, error) {
	id, err := ids.ParseUUID(r.GetRangeId())
	if err != nil {
		return nil, app.ErrNotFound
	}
	d, err := h.svc.FinishRange(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.FinishRangeResponse{Range: rangePB(d.Range, d.Counts), Results: resultsPB(d.Results)}, nil
}

// GetRange implements RangeServiceHandler.
func (h *Handler) GetRange(ctx context.Context, r *pantherclawv1.GetRangeRequest) (*pantherclawv1.GetRangeResponse, error) {
	id, err := ids.ParseUUID(r.GetRangeId())
	if err != nil {
		return nil, app.ErrNotFound
	}
	d, err := h.svc.GetRange(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetRangeResponse{Range: rangePB(d.Range, d.Counts), Results: resultsPB(d.Results)}, nil
}

// ListRanges implements RangeServiceHandler.
func (h *Handler) ListRanges(ctx context.Context, r *pantherclawv1.ListRangesRequest) (*pantherclawv1.ListRangesResponse, error) {
	pr, err := page.Parse(r.GetPageSize(), r.GetPageToken())
	if err != nil {
		return nil, err
	}
	var agent *ids.UUID
	if r.GetRangeAgentId() != "" {
		u, err := ids.ParseUUID(r.GetRangeAgentId())
		if err != nil {
			return nil, app.ErrNotFound
		}
		agent = &u
	}
	p, err := h.svc.ListRanges(ctx, agent, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListRangesResponse{NextPageToken: p.Next}
	for _, rg := range p.Items {
		pb := rangePB(rg, p.Counts[rg.ID])
		if _, stored := p.Counts[rg.ID]; !stored {
			pb.Counts = nil // "not collected", not zero
		}
		out.Ranges = append(out.Ranges, pb)
	}
	return out, nil
}

// ExportAssuranceReport implements RangeServiceHandler.
func (h *Handler) ExportAssuranceReport(ctx context.Context, r *pantherclawv1.ExportAssuranceReportRequest) (*pantherclawv1.ExportAssuranceReportResponse, error) {
	id, err := ids.ParseUUID(r.GetRangeId())
	if err != nil {
		return nil, app.ErrNotFound
	}
	pack, err := h.svc.ExportAssuranceReport(ctx, id)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.ExportAssuranceReportResponse{PackId: pack.String()}, nil
}

var states = map[domain.State]pantherclawv1.RangeState{
	domain.Running:   pantherclawv1.RangeState_RANGE_STATE_RUNNING,
	domain.Finished:  pantherclawv1.RangeState_RANGE_STATE_FINISHED,
	domain.Abandoned: pantherclawv1.RangeState_RANGE_STATE_ABANDONED,
}

func rangePB(r domain.Range, c domain.Counts) *pantherclawv1.Range {
	out := &pantherclawv1.Range{
		Id: r.ID.String(), RangeAgentId: r.Agent.String(), StartedBy: r.StartedBy, RunnerVersion: r.RunnerVersion,
		ScenarioSetDigest: r.SetDigest, State: states[r.State], StartTime: timestamppb.New(r.Started), Origin: r.Origin,
		Counts: &pantherclawv1.RangeCounts{
			Pass: int32(c.Pass), Fail: int32(c.Fail), Error: int32(c.Error), Skipped: int32(c.Skipped), Missing: int32(c.Missing), //nolint:gosec // G115: at most 200
		},
	}
	if r.Baseline != nil {
		out.BaselineRangeId = r.Baseline.String()
	}
	if r.Finished != nil {
		out.FinishTime = timestamppb.New(*r.Finished)
	}
	for _, s := range r.Scenarios {
		out.Scenarios = append(out.Scenarios, &pantherclawv1.RangeScenarioDecl{
			Id: s.ID, Digest: s.Digest, Tier: s.Tier, Category: s.Category, Suite: s.Suite, Title: s.Title, StepCount: int32(s.StepCount), //nolint:gosec // G115: at most 40
		})
	}
	return out
}

func expectPB(e domain.Expect) *pantherclawv1.RangeExpect {
	return &pantherclawv1.RangeExpect{Outcome: e.Outcome, Reason: e.Reason, Code: e.Code}
}

func resultsPB(rs []domain.Result) []*pantherclawv1.RangeResult {
	out := make([]*pantherclawv1.RangeResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, resultPB(r))
	}
	return out
}

func resultPB(r domain.Result) *pantherclawv1.RangeResult {
	out := &pantherclawv1.RangeResult{
		ScenarioId: r.Scenario.ID, ScenarioDigest: r.Scenario.Digest, Category: r.Scenario.Category, Tier: r.Scenario.Tier,
		Verdict: verdictPB(r.Verdict), RecordTime: timestamppb.New(r.Recorded), Origin: domain.OriginOf(r.Scenario.ID),
	}
	if r.Claimed != "" {
		out.ClaimedVerdict = verdictPB(r.Claimed)
	}
	for _, s := range r.Steps {
		st := &pantherclawv1.RangeStep{
			StepId: s.ID, Expect: expectPB(s.Expect), Observed: expectPB(s.Observed), Mismatch: s.Mismatch, Matched: s.Matched,
			DecisiveControl: s.Decisive, Kind: s.Kind, ProbeKind: s.ProbeKind,
		}
		if s.ObservedBy == domain.Server {
			st.ObservedBy = pantherclawv1.RangeObservedBy_RANGE_OBSERVED_BY_SERVER
		} else {
			st.ObservedBy = pantherclawv1.RangeObservedBy_RANGE_OBSERVED_BY_CLIENT
		}
		if s.Mismatch {
			st.Claimed = expectPB(s.Claimed)
		}
		if s.Transaction != nil {
			st.TransactionId = s.Transaction.String()
		}
		if s.Probe != nil {
			st.ProbeReportId = s.Probe.String()
		}
		out.Steps = append(out.Steps, st)
	}
	return out
}
