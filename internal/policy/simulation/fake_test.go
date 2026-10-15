// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation_test

import (
	"context"
	"slices"
	"sync"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var (
	org     = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000b1")
	version = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000b2").UUID()
	now     = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
)

// memStore is an in-memory simulation store for one org.
type memStore struct {
	mu        sync.Mutex
	sims      map[ids.UUID]simulation.Simulation
	samples   map[ids.UUID][]simulation.Sample
	recorded  []simulation.Recorded // newest first
	retention int
	enqueued  []ids.UUID
	audits    []audit.Event
}

func newMemStore() *memStore {
	return &memStore{sims: map[ids.UUID]simulation.Simulation{}, samples: map[ids.UUID][]simulation.Sample{}, retention: 90}
}

func (m *memStore) InTx(ctx context.Context, o ids.OrgID, _ bool, fn func(context.Context, simulation.Tx) error) error {
	if o != org {
		return simulation.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(ctx, m)
}

func (m *memStore) RetentionDays(context.Context) (int, error) { return m.retention, nil }

func (m *memStore) Insert(_ context.Context, s simulation.NewSimulation) (simulation.Simulation, error) {
	for _, x := range m.sims {
		if x.State == simulation.Queued || x.State == simulation.Running {
			return simulation.Simulation{}, simulation.ErrBusy
		}
	}
	out := simulation.Simulation{
		ID: s.ID, Version: s.Version, ContentDigest: s.ContentDigest, WindowStart: now.AddDate(0, 0, -s.Days), WindowEnd: now,
		Max: s.Max, State: simulation.Queued, Report: simulation.NewReport(), RequestedBy: s.RequestedBy, Created: now,
	}
	m.sims[s.ID] = out
	return out, nil
}

func (m *memStore) Get(_ context.Context, id ids.UUID, _ bool) (simulation.Simulation, error) {
	s, ok := m.sims[id]
	if !ok {
		return s, simulation.ErrNotFound
	}
	return s, nil
}

func (m *memStore) List(context.Context, ids.UUID, int32) ([]simulation.Simulation, error) {
	var out []simulation.Simulation
	for _, s := range m.sims {
		out = append(out, s)
	}
	return out, nil
}

func (m *memStore) Start(_ context.Context, id ids.UUID) (simulation.Simulation, bool, error) {
	s := m.sims[id]
	if s.State != simulation.Queued {
		return s, false, nil
	}
	s.State = simulation.Running
	m.sims[id] = s
	return s, true, nil
}

func (m *memStore) Advance(_ context.Context, s simulation.Simulation) (simulation.Simulation, bool, error) {
	if m.sims[s.ID].State != simulation.Running {
		return s, false, nil
	}
	m.sims[s.ID] = s
	return s, true, nil
}

func (m *memStore) Cancel(_ context.Context, id ids.UUID) (simulation.Simulation, bool, error) {
	s := m.sims[id]
	if s.State != simulation.Queued && s.State != simulation.Running {
		return s, false, nil
	}
	s.State = simulation.Cancelled
	m.sims[id] = s
	return s, true, nil
}

func (m *memStore) Receipts(_ context.Context, s simulation.Simulation, limit int) ([]simulation.Recorded, error) {
	start := 0
	if c := s.Cursor; c != nil {
		start = slices.IndexFunc(m.recorded, func(r simulation.Recorded) bool {
			return r.Transaction == c.Transaction && r.Evaluation == c.Evaluation
		}) + 1
	}
	return m.recorded[start:min(len(m.recorded), start+limit)], nil
}

func (m *memStore) SampleCounts(_ context.Context, id ids.UUID) (map[replay.Category]map[string]int, error) {
	out := map[replay.Category]map[string]int{}
	for _, s := range m.samples[id] {
		if out[s.Category] == nil {
			out[s.Category] = map[string]int{}
		}
		out[s.Category][s.Operation]++
	}
	return out, nil
}

func (m *memStore) InsertSample(_ context.Context, id ids.UUID, s simulation.Sample) error {
	m.samples[id] = append(m.samples[id], s)
	return nil
}

func (m *memStore) Samples(_ context.Context, id ids.UUID, f simulation.SampleFilter, _ simulation.SampleKey, _ int32) ([]simulation.Sample, error) {
	var out []simulation.Sample
	for _, s := range m.samples[id] {
		if (f.Category == "" || s.Category == f.Category) && (f.Operation == "" || s.Operation == f.Operation) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *memStore) Enqueue(_ context.Context, id ids.UUID) error {
	m.enqueued = append(m.enqueued, id)
	return nil
}

func (m *memStore) Audit(_ context.Context, ev audit.Event) error {
	m.audits = append(m.audits, ev)
	return nil
}

// outcome is what a fake replay returns for one evaluation: the recorded
// decision, and what the version decides.
type outcome struct {
	orig, prop             adomain.Decision
	origReason, propReason string
	// notReproduced: the replay with the recorded policy differs;
	// incomplete: the replay under the version lacks inputs.
	notReproduced, incomplete bool
	// rule is the decisive policy rule under the version.
	rule string
}

type fakeReplay struct {
	mu    sync.Mutex
	byTxn map[ids.UUID]outcome
	calls int
	// onReplay runs before each replay (to cancel mid-run).
	onReplay func()
}

func (f *fakeReplay) Replay(_ context.Context, _ ids.OrgID, txn ids.UUID, ev int, proposed *ids.UUID) (*replay.Outcome, error) {
	f.mu.Lock()
	f.calls++
	o := f.byTxn[txn]
	hook := f.onReplay
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	out := &replay.Outcome{
		Transaction: txn, Evaluation: ev, Proposed: proposed != nil, Complete: true,
		Original: replay.Original{Decision: o.orig, Reason: o.origReason},
	}
	if proposed == nil {
		out.Decision, out.Reason, out.SameDecision, out.Reproduced = o.orig, o.origReason, true, !o.notReproduced
		return out, nil
	}
	if o.incomplete {
		out.Complete = false
		out.Incomplete = []replay.Limitation{{Code: replay.IncompleteInputUnavailable, Detail: "fact payments.charge.state was never read"}}
		return out, nil
	}
	out.Decision, out.Reason = o.prop, o.propReason
	if o.rule != "" {
		out.Checklist = []pipeline.Item{{Decisive: true, Code: o.propReason, Level: "policy org-policy@2 rule " + o.rule}}
	}
	return out, nil
}

type versions struct{ b *pdomain.Bundle }

func (v versions) PolicyVersion(_ context.Context, _ ids.OrgID, id ids.UUID) (*pdomain.Bundle, error) {
	if id != version {
		return nil, replay.ErrNotFound
	}
	return v.b, nil
}

type editions billing.Edition

func (e editions) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e), Status: billing.StatusValid}, nil
}

var proposedBundle = &pdomain.Bundle{ID: "org-policy", Version: 2, Rules: []pdomain.Rule{
	{
		ID: "hold-large", Kind: pdomain.RequireApproval, Summary: "large refunds need approval", Operations: []string{"payments.refund.create"},
		When: "true", Reason: "REFUND_LARGE", Approval: &pdomain.ApprovalRequirement{Role: "refund_approver", Count: 1},
	},
	{
		ID: "step-up", Kind: pdomain.RequireStepUp, Summary: "a step-up", Operations: []string{"payments.refund.create"},
		When: "true", Reason: "STEP_UP_NEEDED", StepUp: &pdomain.StepUpRequirement{Subject: "principal"},
	},
}}

// as returns ctx for a person of org holding role at the org.
func as(role td.RoleName) context.Context {
	bs := []td.Binding{}
	if role != "" {
		bs = append(bs, td.Binding{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bs,
	}})
}
