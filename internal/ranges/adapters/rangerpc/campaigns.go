// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rangerpc

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	capp "github.com/katocxl/pantherclaw/internal/campaigns/app"
	cdomain "github.com/katocxl/pantherclaw/internal/campaigns/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// errNoCampaigns answers on a server wired without campaigns.
var errNoCampaigns = pcerr.New(pcerr.Unavailable, "CAMPAIGNS_UNAVAILABLE", "attack campaigns are not available on this server")

// WithCampaigns serves the campaign procedures of RangeService (G0 M25 D309).
func (h *Handler) WithCampaigns(svc *capp.Service) *Handler {
	h.campaigns = svc
	return h
}

// StartCampaign implements RangeServiceHandler.
func (h *Handler) StartCampaign(ctx context.Context, r *pantherclawv1.StartCampaignRequest) (*pantherclawv1.StartCampaignResponse, error) {
	if h.campaigns == nil {
		return nil, errNoCampaigns
	}
	agent, err := ids.ParseUUID(r.GetRangeAgentId())
	if err != nil {
		return nil, capp.ErrAgentMissing
	}
	relay, err := ids.ParseUUID(r.GetRelayConnectionId())
	if err != nil {
		return nil, capp.ErrRelay
	}
	in := capp.StartInput{
		Agent: agent, RunnerVersion: r.GetRunnerVersion(), ImageDigest: r.GetImageDigest(), ModelHost: r.GetModelHost(), Relay: relay, Scripted: r.GetScripted(),
	}
	for _, d := range r.GetCampaigns() {
		in.Campaigns = append(in.Campaigns, capp.Decl{ID: d.GetId(), Digest: d.GetDigest()})
	}
	c, err := h.campaigns.StartCampaign(ctx, in)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.StartCampaignResponse{CampaignId: c.ID.String(), StartTime: timestamppb.New(c.Started)}, nil
}

// FinishCampaign implements RangeServiceHandler.
func (h *Handler) FinishCampaign(ctx context.Context, r *pantherclawv1.FinishCampaignRequest) (*pantherclawv1.FinishCampaignResponse, error) {
	if h.campaigns == nil {
		return nil, errNoCampaigns
	}
	id, err := ids.ParseUUID(r.GetCampaignId())
	if err != nil {
		return nil, capp.ErrNotFound
	}
	runs := make([]capp.RunReport, 0, len(r.GetRuns()))
	for _, x := range r.GetRuns() {
		run, err := ids.ParseUUID(x.GetRunId())
		if err != nil {
			return nil, capp.ErrRecord
		}
		rep := capp.RunReport{Scenario: x.GetScenarioId(), Run: run}
		for _, rt := range x.GetRoutes() {
			rep.Routes = append(rep.Routes, cdomain.Route{Kind: rt.GetKind(), Locator: rt.GetLocator()})
		}
		runs = append(runs, rep)
	}
	d, err := h.campaigns.FinishCampaign(ctx, id, runs)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.FinishCampaignResponse{Campaign: campaignPB(d.Campaign, d.Counts), Steps: stepsPB(d.Steps)}, nil
}

// GetCampaign implements RangeServiceHandler.
func (h *Handler) GetCampaign(ctx context.Context, r *pantherclawv1.GetCampaignRequest) (*pantherclawv1.GetCampaignResponse, error) {
	if h.campaigns == nil {
		return nil, errNoCampaigns
	}
	id, err := ids.ParseUUID(r.GetCampaignId())
	if err != nil {
		return nil, capp.ErrNotFound
	}
	d, err := h.campaigns.GetCampaign(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.GetCampaignResponse{Campaign: campaignPB(d.Campaign, d.Counts), Steps: stepsPB(d.Steps)}
	for _, u := range d.Usage {
		out.ModelUsage = append(out.ModelUsage, &pantherclawv1.CampaignModelUsage{
			RunId: u.Run.String(), ScenarioId: u.Scenario, ModelHost: u.ModelHost, Requests: u.Requests,
			BytesToModel: u.BytesToModel, BytesFromModel: u.BytesFromModel,
		})
	}
	return out, nil
}

// ListCampaigns implements RangeServiceHandler.
func (h *Handler) ListCampaigns(ctx context.Context, r *pantherclawv1.ListCampaignsRequest) (*pantherclawv1.ListCampaignsResponse, error) {
	if h.campaigns == nil {
		return nil, errNoCampaigns
	}
	pr, err := page.Parse(r.GetPageSize(), r.GetPageToken())
	if err != nil {
		return nil, err
	}
	var agent *ids.UUID
	if s := r.GetRangeAgentId(); s != "" {
		a, err := ids.ParseUUID(s)
		if err != nil {
			return nil, capp.ErrAgentMissing
		}
		agent = &a
	}
	p, err := h.campaigns.ListCampaigns(ctx, agent, pr)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListCampaignsResponse{NextPageToken: p.Next}
	for _, c := range p.Items {
		out.Campaigns = append(out.Campaigns, campaignPB(c, p.Counts[c.ID]))
	}
	return out, nil
}

var campaignStates = map[cdomain.State]pantherclawv1.CampaignState{
	cdomain.Running:   pantherclawv1.CampaignState_CAMPAIGN_STATE_RUNNING,
	cdomain.Finished:  pantherclawv1.CampaignState_CAMPAIGN_STATE_FINISHED,
	cdomain.Abandoned: pantherclawv1.CampaignState_CAMPAIGN_STATE_ABANDONED,
}

var campaignOutcomes = map[cdomain.Outcome]pantherclawv1.CampaignOutcome{
	cdomain.Held:              pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_HELD,
	cdomain.Denied:            pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_DENIED,
	cdomain.NotRoutedReported: pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_NOT_ROUTED_REPORTED,
	cdomain.Allowed:           pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_ALLOWED,
	cdomain.NotExercised:      pantherclawv1.CampaignOutcome_CAMPAIGN_OUTCOME_NOT_EXERCISED,
}

var campaignBases = map[cdomain.Basis]pantherclawv1.CampaignBasis{
	cdomain.ServerRecord: pantherclawv1.CampaignBasis_CAMPAIGN_BASIS_SERVER_RECORD,
	cdomain.EdgeReport:   pantherclawv1.CampaignBasis_CAMPAIGN_BASIS_EDGE_REPORT,
	cdomain.NoBasis:      pantherclawv1.CampaignBasis_CAMPAIGN_BASIS_NONE,
}

func campaignPB(c cdomain.Campaign, n cdomain.Counts) *pantherclawv1.Campaign {
	out := &pantherclawv1.Campaign{
		Id: c.ID.String(), RangeAgentId: c.Agent.String(), StartedBy: c.StartedBy, RunnerVersion: c.RunnerVersion, SetDigest: c.SetDigest,
		ScenarioIds: c.Scenarios, ImageDigest: c.ImageDigest, ModelHost: c.ModelHost, RelayConnectionId: c.Relay.String(), Scripted: c.Scripted,
		State: campaignStates[c.State], StartTime: timestamppb.New(c.Started), Origin: cdomain.Origin, Statement: c.Statement(),
		Counts: &pantherclawv1.CampaignCounts{
			Held: int32(n.Held), Denied: int32(n.Denied), NotRoutedReported: int32(n.NotRoutedReported), //nolint:gosec // G115: a few attempts per campaign
			Allowed: int32(n.Allowed), NotExercised: int32(n.NotExercised), //nolint:gosec // G115: as above
		},
	}
	if c.Finished != nil {
		out.FinishTime = timestamppb.New(*c.Finished)
	}
	return out
}

func stepsPB(steps []cdomain.Step) []*pantherclawv1.CampaignStep {
	out := make([]*pantherclawv1.CampaignStep, 0, len(steps))
	for _, s := range steps {
		st := &pantherclawv1.CampaignStep{
			ScenarioId: s.Scenario, StepId: s.ID, Boundary: s.Boundary, Expected: string(s.Expected), Outcome: campaignOutcomes[s.Outcome],
			Basis: campaignBases[s.Basis], Reason: s.Reason, RouteLocator: s.Route,
		}
		if s.Transaction != nil {
			st.TransactionId = s.Transaction.String()
		}
		out = append(out, st)
	}
	return out
}
