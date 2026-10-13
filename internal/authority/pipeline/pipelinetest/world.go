// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pipelinetest is an in-memory world for decision pipeline tests:
// a pinned package, a policy, agents, runs, grants and guardrails (through
// grantstest), facts, budget usage and dedupe claims. Every read can be
// made to fail, to show the pipeline fails closed.
package pipelinetest

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// ErrInjected is the error an injected failure returns.
var ErrInjected = errors.New("pipelinetest: injected failure")

// World implements pipeline.Reader.
type World struct {
	mu       sync.Mutex
	Org      ids.OrgID
	Grants   *grantstest.Store
	Cont     pipeline.Containment
	pkg      *defs.Package
	states   map[string]defs.State // operation → lifecycle state
	policy   *pipeline.Policy
	runs     map[ids.UUID]pipeline.Run
	agents   map[ids.UUID]pipeline.Agent
	facts    map[string]map[string]fdomain.Fact // subject → name → fact
	accounts map[bdomain.Ref]bdomain.Account
	counters map[bdomain.Ref]bdomain.Counter
	claims   map[string]*pipeline.Claim
	conns    map[ids.UUID]pipeline.Connection
	// Fail makes the named Reader method return ErrInjected.
	Fail  map[string]bool
	hold  *holdState
	final *finalState
}

// New returns a world for org with p pinned and every definition ACTIVE.
func New(org ids.OrgID, p *defs.Package, now time.Time) *World {
	w := &World{
		Org: org, Grants: grantstest.New(org), Cont: pipeline.Containment{Epoch: 1, Now: now},
		pkg: p, states: map[string]defs.State{}, runs: map[ids.UUID]pipeline.Run{}, agents: map[ids.UUID]pipeline.Agent{},
		facts: map[string]map[string]fdomain.Fact{}, accounts: map[bdomain.Ref]bdomain.Account{},
		counters: map[bdomain.Ref]bdomain.Counter{}, claims: map[string]*pipeline.Claim{}, Fail: map[string]bool{},
		conns: map[ids.UUID]pipeline.Connection{},
	}
	for _, d := range p.Definitions {
		w.states[d.Operation] = defs.StateActive
	}
	return w
}

// SetState sets a definition's lifecycle state.
func (w *World) SetState(op string, s defs.State) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.states[op] = s
}

// SetPolicy compiles and publishes rules, with the given fact catalog.
func (w *World) SetPolicy(rules []pdomain.Rule, catalog map[string]fdomain.Type) error {
	e := &papp.Engine{Limits: celenv.DefaultLimits, Facts: catalog}
	var ds []*defs.Definition
	for i := range w.pkg.Definitions {
		ds = append(ds, &w.pkg.Definitions[i])
	}
	c, err := e.Compile(&pdomain.Bundle{ID: "org-policy", Version: 1, Rules: rules}, ds)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.policy = &pipeline.Policy{Compiled: c, Version: "org-policy@1", Budget: papp.DefaultBudget}
	return nil
}

// AddAgent registers an agent.
func (w *World) AddAgent(id ids.UUID, a pipeline.Agent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.agents[id] = a
}

// AddRun registers a run.
func (w *World) AddRun(id ids.UUID, r pipeline.Run) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.runs[id] = r
}

// PutFact records a fact about a subject.
func (w *World) PutFact(f fdomain.Fact) {
	w.mu.Lock()
	defer w.mu.Unlock()
	key := f.SubjectType + "/" + f.SubjectID
	if w.facts[key] == nil {
		w.facts[key] = map[string]fdomain.Fact{}
	}
	w.facts[key][f.Name] = f
}

// SetClaim records the latest attempt on a dedupe key.
func (w *World) SetClaim(key string, c pipeline.Claim) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.claims[key] = &c
}

// Reserve applies an allowed evaluation's plan to the usage, as the
// finalization would.
func (w *World) Reserve(e *pipeline.Evaluation) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, d := range e.Plan.Budgets {
		a := w.accounts[d.Ref]
		a.Reserved, _ = a.Reserved.Add(d.Amount)
		a.ReservedCount++
		w.accounts[d.Ref] = a
	}
	for _, d := range e.Plan.Counters {
		c := w.counters[d.Ref]
		c.Reserved++
		w.counters[d.Ref] = c
	}
}

func (w *World) fail(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Fail[name] {
		return ErrInjected
	}
	return nil
}

// Containment implements pipeline.Reader.
func (w *World) Containment(context.Context, ids.OrgID) (pipeline.Containment, error) {
	if err := w.fail("Containment"); err != nil {
		return pipeline.Containment{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.Cont, nil
}

// Definition implements pipeline.Reader.
func (w *World) Definition(_ context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	if err := w.fail("Definition"); err != nil {
		return pipeline.Pinned{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if org != w.Org || pin.Package != w.pkg.Name || pin.Version != w.pkg.Version {
		return pipeline.Pinned{}, pipeline.ErrNotFound
	}
	for i := range w.pkg.Definitions {
		if d := &w.pkg.Definitions[i]; d.Digest == pin.Digest {
			return pipeline.Pinned{Definition: d, State: w.states[d.Operation]}, nil
		}
	}
	return pipeline.Pinned{}, pipeline.ErrNotFound
}

// Policy implements pipeline.Reader.
func (w *World) Policy(context.Context, ids.OrgID) (*pipeline.Policy, error) {
	if err := w.fail("Policy"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.policy, nil
}

// Run implements pipeline.Reader.
func (w *World) Run(_ context.Context, _ ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	if err := w.fail("Run"); err != nil {
		return pipeline.Run{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	r, ok := w.runs[id]
	if !ok {
		return pipeline.Run{}, pipeline.ErrNotFound
	}
	return r, nil
}

// Agent implements pipeline.Reader.
func (w *World) Agent(_ context.Context, _ ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	if err := w.fail("Agent"); err != nil {
		return pipeline.Agent{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	a, ok := w.agents[id]
	if !ok {
		return pipeline.Agent{}, pipeline.ErrNotFound
	}
	return a, nil
}

// Chain implements pipeline.Reader.
func (w *World) Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	if err := w.fail("Chain"); err != nil {
		return nil, err
	}
	return w.Grants.Chain(ctx, org, id)
}

// Envelopes implements pipeline.Reader.
func (w *World) Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error) {
	if err := w.fail("Envelopes"); err != nil {
		return nil, err
	}
	return w.Grants.Envelopes(ctx, org, scopes)
}

// Facts implements pipeline.Reader.
func (w *World) Facts(_ context.Context, _ ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	if err := w.fail("Facts"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]fdomain.Fact{}
	for _, n := range names {
		if f, ok := w.facts[subjectType+"/"+subjectID][n]; ok {
			out[n] = f
		}
	}
	return out, nil
}

// Usage implements pipeline.Reader.
func (w *World) Usage(_ context.Context, _ ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	if err := w.fail("Usage"); err != nil {
		return pipeline.Usage{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	u := pipeline.Usage{Accounts: map[bdomain.Ref]bdomain.Account{}, Counters: map[bdomain.Ref]bdomain.Counter{}, CounterRows: map[bdomain.Ref]int{}}
	for _, d := range plan.Budgets {
		if a, ok := w.accounts[d.Ref]; ok {
			u.Accounts[d.Ref] = a
		}
	}
	for _, d := range plan.Counters {
		if c, ok := w.counters[d.Ref]; ok {
			u.Counters[d.Ref] = c
		}
		capRef := d.Ref
		capRef.Key = [32]byte{}
		for ref := range w.counters {
			k := ref
			k.Key = [32]byte{}
			if k == capRef {
				u.CounterRows[capRef]++
			}
		}
	}
	return u, nil
}

// Claim implements pipeline.Reader.
func (w *World) Claim(_ context.Context, _ ids.OrgID, key string) (*pipeline.Claim, error) {
	if err := w.fail("Claim"); err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.claims[key], nil
}

// PutConnection adds or replaces a connection.
func (w *World) PutConnection(c pipeline.Connection) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.conns[c.ID] = c
}

// Connection implements pipeline.Reader.
func (w *World) Connection(_ context.Context, _ ids.OrgID, id ids.UUID) (pipeline.Connection, error) {
	if err := w.fail("Connection"); err != nil {
		return pipeline.Connection{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	c, ok := w.conns[id]
	if !ok {
		return pipeline.Connection{}, pipeline.ErrNotFound
	}
	if c.Reads == nil && c.Package == w.pkg.Name {
		// As PostgreSQL reads them: the pinned package's reads (a
		// connection put with Reads keeps its own).
		c.Reads = w.pkg.HTTPReads()
	}
	return c, nil
}
