// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgcampaigns stores attack campaigns in Postgres (G0 M25 D309,
// migration 00281) as the campaign service's store, reads the server's own
// run and transaction records outcomes are derived from, serves compliance
// its results and abandons campaigns nobody finished.
package pgcampaigns

import (
	"context"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/campaigns/app"
	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/campaigns/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store is the campaign store over a connection pool. It is also the
// compliance read port.
type Store struct{ Pool *db.Pool }

var (
	_ app.Store          = Store{}
	_ ports.ResultReader = Store{}
)

// InTx runs fn in a tenant transaction for org.
func (s Store) InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(context.Context, app.Tx) error) error {
	var opts []db.TxOption
	if readOnly {
		opts = append(opts, db.ReadOnly())
	}
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, &txn{org: org, tx: tx, q: dbq.New(tx)})
	}, opts...)
}

type txn struct {
	org ids.OrgID
	tx  db.TenantTx
	q   *dbq.Queries
}

func (t *txn) Agent(ctx context.Context, id ids.UUID) (app.AgentRef, error) {
	a, err := t.q.GetAgent(ctx, t.org, id)
	if db.IsNoRows(err) {
		return app.AgentRef{}, app.ErrAgentMissing
	} else if err != nil {
		return app.AgentRef{}, err
	}
	path, err := agents.PathOf(ctx, t.q, a)
	if err != nil {
		return app.AgentRef{}, err
	}
	return app.AgentRef{ID: a.ID, RangeAgent: a.RangeAgent, Path: path}, nil
}

func (t *txn) Connection(ctx context.Context, id ids.UUID) (app.ConnectionRef, bool, error) {
	c, err := t.q.GetConnection(ctx, t.org, id)
	if db.IsNoRows(err) {
		return app.ConnectionRef{}, false, nil
	} else if err != nil {
		return app.ConnectionRef{}, false, err
	}
	return app.ConnectionRef{ID: c.ID, Simulated: c.Simulated}, true, nil
}

func campaignOf(c dbq.PcCampaign) domain.Campaign {
	return domain.Campaign{
		ID: c.ID, Agent: c.RangeAgentID, StartedBy: c.StartedBy, RunnerVersion: c.RunnerVersion, SetDigest: c.SetDigest, Scenarios: c.ScenarioIds,
		ImageDigest: c.ImageDigest, ModelHost: c.ModelHost, Relay: c.RelayConnectionID, Scripted: c.Scripted, State: domain.State(c.State),
		Started: c.StartedAt, Finished: c.FinishedAt,
	}
}

func (t *txn) Campaign(ctx context.Context, id ids.UUID, lock bool) (domain.Campaign, error) {
	var (
		c   dbq.PcCampaign
		err error
	)
	if lock {
		c, err = t.q.LockCampaign(ctx, t.org, id)
	} else {
		c, err = t.q.GetCampaign(ctx, t.org, id)
	}
	if db.IsNoRows(err) {
		return domain.Campaign{}, app.ErrNotFound
	} else if err != nil {
		return domain.Campaign{}, err
	}
	return campaignOf(c), nil
}

func (t *txn) OpenOf(ctx context.Context, agent ids.UUID) (domain.Campaign, bool, error) {
	c, err := t.q.OpenCampaignOfAgent(ctx, t.org, agent)
	if db.IsNoRows(err) {
		return domain.Campaign{}, false, nil
	} else if err != nil {
		return domain.Campaign{}, false, err
	}
	return campaignOf(c), true, nil
}

func (t *txn) InsertCampaign(ctx context.Context, c domain.Campaign) (domain.Campaign, error) {
	row, err := t.q.InsertCampaign(ctx, dbq.InsertCampaignParams{
		OrgID: t.org, ID: c.ID, RangeAgentID: c.Agent, StartedBy: c.StartedBy, RunnerVersion: c.RunnerVersion, SetDigest: c.SetDigest,
		ScenarioIds: c.Scenarios, ImageDigest: c.ImageDigest, ModelHost: c.ModelHost, RelayConnectionID: c.Relay, Scripted: c.Scripted,
	})
	if db.IsUniqueViolation(err) {
		return domain.Campaign{}, app.ErrOpen // two starts raced for one twin
	} else if err != nil {
		return domain.Campaign{}, err
	}
	return campaignOf(row), nil
}

func (t *txn) Transition(ctx context.Context, id ids.UUID, to domain.State) (time.Time, bool, error) {
	at, err := t.q.TransitionCampaign(ctx, string(to), t.org, id)
	if db.IsNoRows(err) {
		return time.Time{}, false, nil
	} else if err != nil {
		return time.Time{}, false, err
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return *at, true, nil
}

func (t *txn) List(ctx context.Context, agent *ids.UUID, after ids.UUID, limit int32) ([]domain.Campaign, error) {
	rows, err := t.q.ListCampaigns(ctx, dbq.ListCampaignsParams{OrgID: t.org, RangeAgentID: agent, Before: after, PageLimit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Campaign, 0, len(rows))
	for _, r := range rows {
		out = append(out, campaignOf(r))
	}
	return out, nil
}

func (t *txn) CountsOf(ctx context.Context, campaigns []ids.UUID) (map[ids.UUID]domain.Counts, error) {
	return countsOf(ctx, t.q, t.org, campaigns)
}

func countsOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, campaigns []ids.UUID) (map[ids.UUID]domain.Counts, error) {
	out := map[ids.UUID]domain.Counts{}
	if len(campaigns) == 0 {
		return out, nil
	}
	rows, err := q.CampaignStepOutcomes(ctx, org, campaigns)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		c := out[r.CampaignID]
		c.Add(domain.Outcome(r.Outcome), int(r.Steps))
		out[r.CampaignID] = c
	}
	return out, nil
}

func stepOf(s dbq.PcCampaignStep) domain.Step {
	return domain.Step{
		Scenario: s.ScenarioID, ID: s.StepID, Boundary: s.Boundary, Expected: domain.Expected(s.Expected), Outcome: domain.Outcome(s.Outcome),
		Basis: domain.Basis(s.Basis), Transaction: s.TransactionID, Reason: s.Reason, Route: s.RouteLocator,
	}
}

func (t *txn) Steps(ctx context.Context, campaign ids.UUID) ([]domain.Step, error) {
	return stepsOf(ctx, t.q, t.org, campaign)
}

func stepsOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, campaign ids.UUID) ([]domain.Step, error) {
	rows, err := q.ListCampaignSteps(ctx, org, campaign)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Step, 0, len(rows))
	for _, r := range rows {
		out = append(out, stepOf(r))
	}
	return out, nil
}

func (t *txn) InsertStep(ctx context.Context, campaign ids.UUID, s domain.Step) error {
	return t.q.InsertCampaignStep(ctx, dbq.InsertCampaignStepParams{
		OrgID: t.org, CampaignID: campaign, ScenarioID: s.Scenario, StepID: s.ID, Boundary: s.Boundary, Expected: string(s.Expected),
		Outcome: string(s.Outcome), Basis: string(s.Basis), TransactionID: s.Transaction, Reason: s.Reason, RouteLocator: s.Route,
	})
}

func (t *txn) Run(ctx context.Context, id ids.UUID) (domain.RunRecord, bool, error) {
	r, err := t.q.CampaignRunRecord(ctx, t.org, id)
	if db.IsNoRows(err) {
		return domain.RunRecord{}, false, nil
	} else if err != nil {
		return domain.RunRecord{}, false, err
	}
	return domain.RunRecord{ID: r.ID, Agent: r.AgentID, Simulated: r.Simulated, Created: r.CreatedAt}, true, nil
}

func (t *txn) Transactions(ctx context.Context, run ids.UUID) ([]domain.Transaction, error) {
	rows, err := t.q.CampaignRunTransactions(ctx, t.org, run)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Transaction, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Transaction{
			ID: r.ID, Operation: r.Operation, Decision: r.Decision, Reason: r.ReasonCode, Mode: r.Mode, Simulated: r.Simulated,
			Created: r.CreatedAt, Effect: r.EffectState,
		})
	}
	return out, nil
}

func (t *txn) SetRunScenario(ctx context.Context, c domain.Campaign, run ids.UUID, scenario string) error {
	return t.q.SetCampaignRunScenario(ctx, dbq.SetCampaignRunScenarioParams{
		OrgID: t.org, CampaignID: c.ID, RunID: run, ScenarioID: &scenario, ModelHost: c.ModelHost,
	})
}

func (t *txn) Usage(ctx context.Context, campaign ids.UUID) ([]app.Usage, error) {
	rows, err := t.q.ListCampaignRuns(ctx, t.org, campaign)
	if err != nil {
		return nil, err
	}
	out := make([]app.Usage, 0, len(rows))
	for _, r := range rows {
		u := app.Usage{Run: r.RunID, ModelHost: r.ModelHost, Requests: r.Requests, BytesToModel: r.BytesToModel, BytesFromModel: r.BytesFromModel}
		if r.ScenarioID != nil {
			u.Scenario = *r.ScenarioID
		}
		out = append(out, u)
	}
	return out, nil
}

func (t *txn) Audit(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}

// CampaignResults implements ports.ResultReader: finished campaigns only.
func (s Store) CampaignResults(ctx context.Context, org ids.OrgID, f ports.Filter) (ports.Results, error) {
	var out ports.Results
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.FinishedCampaigns(ctx, dbq.FinishedCampaignsParams{
			OrgID: org, FromTime: &f.Start, ToTime: &f.End, RangeAgentID: f.Agent, PageLimit: ports.MaxResults + 1,
		})
		if err != nil {
			return err
		}
		if len(rows) > ports.MaxResults {
			rows, out.Truncated = rows[:ports.MaxResults], true
		}
		for _, r := range rows {
			steps, err := stepsOf(ctx, q, org, r.ID)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, ports.Result{Campaign: campaignOf(r), Steps: steps, Counts: domain.Count(steps)})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
