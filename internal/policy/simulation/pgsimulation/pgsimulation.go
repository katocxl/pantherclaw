// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgsimulation stores policy simulations in Postgres (G0 M11.1
// D15, migration 00113) and runs them as River jobs. It writes only the
// simulation's own rows, its job and its audit events; the recorded
// decisions are read, never written (HR-232).
package pgsimulation

import (
	"context"
	"encoding/json/v2"
	"strings"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
)

// Store is the simulation store over a connection pool. Jobs is an
// insert-only River client; without it no simulation can be queued.
type Store struct {
	Pool *db.Pool
	Jobs *jobs.Client
}

var _ simulation.Store = Store{}

// InTx runs fn in a tenant transaction for org.
func (s Store) InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(context.Context, simulation.Tx) error) error {
	var opts []db.TxOption
	if readOnly {
		opts = append(opts, db.ReadOnly())
	}
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, &txn{org: org, tx: tx, q: dbq.New(tx), jobs: s.Jobs})
	}, opts...)
}

type txn struct {
	org  ids.OrgID
	tx   db.TenantTx
	q    *dbq.Queries
	jobs *jobs.Client
}

// Stored forms. The keys are part of the schema of the jsonb columns.
type (
	workflowJSON struct {
		Operations map[string]map[string]int `json:"operations"`
		Agents     map[string]map[string]int `json:"agents"`
	}
	burdenJSON struct {
		PerDay map[string]int `json:"per_day"`
		ByRole map[string]int `json:"by_role"`
	}
)

func countsJSON(c simulation.Counts) map[string]int {
	out := make(map[string]int, len(c))
	for k, v := range c {
		out[string(k)] = v
	}
	return out
}

func countsOf(m map[string]int) simulation.Counts {
	out := simulation.Counts{}
	for k, v := range m {
		out[replay.Category(k)] = v
	}
	return out
}

func groupsJSON(g map[string]simulation.Counts) map[string]map[string]int {
	out := make(map[string]map[string]int, len(g))
	for k, c := range g {
		out[k] = countsJSON(c)
	}
	return out
}

func groupsOf(m map[string]map[string]int) map[string]simulation.Counts {
	out := make(map[string]simulation.Counts, len(m))
	for k, c := range m {
		out[k] = countsOf(c)
	}
	return out
}

func simulationOf(r dbq.PcPolicySimulation) (simulation.Simulation, error) {
	s := simulation.Simulation{
		ID: r.ID, Version: r.VersionID, WindowStart: r.WindowStart, WindowEnd: r.WindowEnd, Max: int(r.MaxEvaluations),
		State: simulation.State(r.State), Evaluated: int(r.Evaluated), Report: simulation.NewReport(), RequestedBy: r.RequestedBy,
		Created: r.CreatedAt, Started: r.StartedAt, Finished: r.FinishedAt,
	}
	copy(s.ContentDigest[:], r.ContentDigest)
	if r.Error != nil {
		s.Error = *r.Error
	}
	if r.CursorCreatedAt != nil && r.CursorTxn != nil && r.CursorEvaluation != nil {
		s.Cursor = &simulation.Cursor{Created: *r.CursorCreatedAt, Transaction: *r.CursorTxn, Evaluation: int(*r.CursorEvaluation)}
	}
	var counts map[string]int
	if err := json.Unmarshal(r.Counts, &counts); err != nil {
		return s, err
	}
	var wf workflowJSON
	if err := json.Unmarshal(r.ByWorkflow, &wf); err != nil {
		return s, err
	}
	var b burdenJSON
	if err := json.Unmarshal(r.Burden, &b); err != nil {
		return s, err
	}
	s.Report.Counts, s.Report.ByOperation, s.Report.ByAgent = countsOf(counts), groupsOf(wf.Operations), groupsOf(wf.Agents)
	if b.PerDay != nil {
		s.Report.HeldPerDay = b.PerDay
	}
	if b.ByRole != nil {
		s.Report.HeldByRole = b.ByRole
	}
	return s, nil
}

// RetentionDays implements simulation.Tx: the shorter of the replay
// inputs' and the receipts' retention in effect now.
func (t *txn) RetentionDays(ctx context.Context) (int, error) {
	facts, _ := retention.BoundsOf(retention.NormalizedFacts)
	receipts, _ := retention.BoundsOf(retention.Receipts)
	n, err := t.q.SimulationRetentionDays(ctx, int32(facts.Default), int32(receipts.Default)) //nolint:gosec // G115: days ≤ 3650
	return int(n), err
}

// Insert implements simulation.Tx.
func (t *txn) Insert(ctx context.Context, s simulation.NewSimulation) (simulation.Simulation, error) {
	row, err := t.q.InsertPolicySimulation(ctx, dbq.InsertPolicySimulationParams{
		OrgID: t.org, ID: s.ID, VersionID: s.Version, ContentDigest: s.ContentDigest[:], Days: int32(s.Days), //nolint:gosec // ≤ 30
		MaxEvaluations: int32(s.Max), RequestedBy: s.RequestedBy, //nolint:gosec // ≤ 50 000
	})
	switch {
	case db.IsUniqueViolation(err):
		return simulation.Simulation{}, simulation.ErrBusy
	case db.IsForeignKeyViolation(err):
		return simulation.Simulation{}, simulation.ErrVersionNotFound
	case err != nil:
		return simulation.Simulation{}, err
	}
	return simulationOf(row)
}

// Get implements simulation.Tx.
func (t *txn) Get(ctx context.Context, id ids.UUID, lock bool) (simulation.Simulation, error) {
	get := t.q.GetPolicySimulation
	if lock {
		get = t.q.LockPolicySimulation
	}
	row, err := get(ctx, t.org, id)
	if db.IsNoRows(err) {
		return simulation.Simulation{}, simulation.ErrNotFound
	} else if err != nil {
		return simulation.Simulation{}, err
	}
	return simulationOf(row)
}

// List implements simulation.Tx.
func (t *txn) List(ctx context.Context, before ids.UUID, limit int32) ([]simulation.Simulation, error) {
	rows, err := t.q.ListPolicySimulations(ctx, t.org, optional(before), limit)
	if err != nil {
		return nil, err
	}
	out := make([]simulation.Simulation, 0, len(rows))
	for _, r := range rows {
		s, err := simulationOf(r)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (t *txn) changed(row dbq.PcPolicySimulation, err error) (simulation.Simulation, bool, error) {
	if db.IsNoRows(err) {
		return simulation.Simulation{}, false, nil
	} else if err != nil {
		return simulation.Simulation{}, false, err
	}
	s, err := simulationOf(row)
	return s, err == nil, err
}

// Start implements simulation.Tx.
func (t *txn) Start(ctx context.Context, id ids.UUID) (simulation.Simulation, bool, error) {
	return t.changed(t.q.StartPolicySimulation(ctx, t.org, id))
}

// Cancel implements simulation.Tx.
func (t *txn) Cancel(ctx context.Context, id ids.UUID) (simulation.Simulation, bool, error) {
	return t.changed(t.q.CancelPolicySimulation(ctx, t.org, id))
}

// Advance implements simulation.Tx.
func (t *txn) Advance(ctx context.Context, s simulation.Simulation) (simulation.Simulation, bool, error) {
	counts, err := json.Marshal(countsJSON(s.Report.Counts))
	if err != nil {
		return simulation.Simulation{}, false, err
	}
	wf, err := json.Marshal(workflowJSON{Operations: groupsJSON(s.Report.ByOperation), Agents: groupsJSON(s.Report.ByAgent)})
	if err != nil {
		return simulation.Simulation{}, false, err
	}
	burden, err := json.Marshal(burdenJSON{PerDay: s.Report.HeldPerDay, ByRole: s.Report.HeldByRole})
	if err != nil {
		return simulation.Simulation{}, false, err
	}
	p := dbq.AdvancePolicySimulationParams{
		State: string(s.State), Evaluated: int32(s.Evaluated), Counts: counts, ByWorkflow: wf, Burden: burden, //nolint:gosec // ≤ 50 000
		OrgID: t.org, ID: s.ID,
	}
	if c := s.Cursor; c != nil {
		ev := int32(c.Evaluation) //nolint:gosec // G115: 1..64
		p.CursorCreatedAt, p.CursorTxn, p.CursorEvaluation = &c.Created, &c.Transaction, &ev
	}
	if s.Error != "" {
		p.Error = &s.Error
	}
	return t.changed(t.q.AdvancePolicySimulation(ctx, p))
}

// Receipts implements simulation.Tx.
func (t *txn) Receipts(ctx context.Context, s simulation.Simulation, limit int) ([]simulation.Recorded, error) {
	if limit <= 0 {
		return nil, nil
	}
	p := dbq.SimulationReceiptsParams{OrgID: t.org, WindowStart: s.WindowStart, WindowEnd: s.WindowEnd, PageLimit: int32(limit)} //nolint:gosec // ≤ chunk
	if c := s.Cursor; c != nil {
		ev := int32(c.Evaluation) //nolint:gosec // G115: 1..64
		p.CursorCreatedAt, p.CursorTxn, p.CursorEvaluation = &c.Created, &c.Transaction, &ev
	}
	rows, err := t.q.SimulationReceipts(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]simulation.Recorded, 0, len(rows))
	for _, r := range rows {
		out = append(out, simulation.Recorded{
			Transaction: r.TransactionID, Evaluation: int(r.Evaluation), Created: r.CreatedAt, Agent: r.AgentID, Operation: r.Operation,
		})
	}
	return out, nil
}

// SampleCounts implements simulation.Tx.
func (t *txn) SampleCounts(ctx context.Context, id ids.UUID) (map[replay.Category]map[string]int, error) {
	rows, err := t.q.SimulationSampleCounts(ctx, t.org, id)
	if err != nil {
		return nil, err
	}
	out := map[replay.Category]map[string]int{}
	for _, r := range rows {
		c := replay.Category(r.Category)
		if out[c] == nil {
			out[c] = map[string]int{}
		}
		out[c][r.Operation] = int(r.N)
	}
	return out, nil
}

// InsertSample implements simulation.Tx.
func (t *txn) InsertSample(ctx context.Context, id ids.UUID, s simulation.Sample) error {
	return t.q.InsertSimulationSample(ctx, dbq.InsertSimulationSampleParams{
		OrgID: t.org, SimulationID: id, Category: string(s.Category), TransactionID: s.Transaction,
		Evaluation: int32(s.Evaluation), AgentID: s.Agent, Operation: s.Operation, //nolint:gosec // G115: 1..64
		OriginalDecision: s.Original, OriginalReason: s.OrigReason, ProposedDecision: s.Proposed, ProposedReason: s.PropReason,
		Limitation: strings.Join(s.Limitations, ","),
	})
}

// Samples implements simulation.Tx.
func (t *txn) Samples(ctx context.Context, id ids.UUID, f simulation.SampleFilter, after simulation.SampleKey, limit int32) ([]simulation.Sample, error) {
	rows, err := t.q.ListSimulationSamples(ctx, dbq.ListSimulationSamplesParams{
		OrgID: t.org, SimulationID: id, Category: string(f.Category), Operation: f.Operation,
		AfterTxn: optional(after.Transaction), AfterEvaluation: int32(after.Evaluation), PageLimit: limit, //nolint:gosec // G115: 0..64
	})
	if err != nil {
		return nil, err
	}
	out := make([]simulation.Sample, 0, len(rows))
	for _, r := range rows {
		s := simulation.Sample{
			Category: replay.Category(r.Category), Transaction: r.TransactionID, Evaluation: int(r.Evaluation), Agent: r.AgentID,
			Operation: r.Operation, Original: r.OriginalDecision, OrigReason: r.OriginalReason, Proposed: r.ProposedDecision,
			PropReason: r.ProposedReason,
		}
		if r.Limitation != "" {
			s.Limitations = strings.Split(r.Limitation, ",")
		}
		out = append(out, s)
	}
	return out, nil
}

// Enqueue implements simulation.Tx: the simulation's job, in the
// transaction that stores it.
func (t *txn) Enqueue(ctx context.Context, id ids.UUID) error {
	if t.jobs == nil {
		return simulation.ErrUnwired
	}
	return jobs.InsertTx(ctx, t.jobs, t.tx, SimulateArgs{Org: t.org, Simulation: id}, nil)
}

// Audit implements simulation.Tx.
func (t *txn) Audit(ctx context.Context, ev audit.Event) error {
	_, err := audit.Record(ctx, t.tx, ev)
	return err
}

// optional is nil for the zero id: no page position.
func optional(id ids.UUID) *ids.UUID {
	if id.IsZero() {
		return nil
	}
	return &id
}
