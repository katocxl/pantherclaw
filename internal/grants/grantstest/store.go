// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package grantstest is an in-memory implementation of the grants ports for
// tests. It enforces the same conditions as the database adapter: writes
// are conditional on what was read, revocation cascades, fan-out is checked
// under one lock, and every removal of authority increments the epoch.
package grantstest

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Store holds one org's grants, envelopes, agents, runs and definitions.
type Store struct {
	mu         sync.Mutex
	Org        ids.OrgID
	grants     map[domain.GrantID][]domain.Grant // revisions, oldest first
	envelopes  map[string]domain.Envelope        // by scope
	agents     map[ids.UUID]app.Agent
	runs       map[ids.UUID]app.Run
	principals map[domain.Principal]bool
	defs       map[string]*defs.Definition
	epoch      int64
	events     []audit.Event
}

// New returns an empty store for org.
func New(org ids.OrgID) *Store {
	return &Store{
		Org: org, grants: map[domain.GrantID][]domain.Grant{}, envelopes: map[string]domain.Envelope{},
		agents: map[ids.UUID]app.Agent{}, runs: map[ids.UUID]app.Run{}, principals: map[domain.Principal]bool{},
		defs: map[string]*defs.Definition{}, epoch: 1,
	}
}

func scopeKey(s domain.Scope) string {
	return string(s.Kind) + "/" + s.ID.String() + "/" + s.Principal.String()
}

// AddAgent registers an agent.
func (s *Store) AddAgent(a app.Agent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.ID] = a
}

// AddRun registers a run.
func (s *Store) AddRun(r app.Run) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[r.ID] = r
}

// AddPrincipal registers an active user or service account.
func (s *Store) AddPrincipal(p domain.Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[p] = true
}

// AddDefinition registers an active definition.
func (s *Store) AddDefinition(d *defs.Definition) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defs[d.Operation] = d
}

// Epoch returns the containment epoch.
func (s *Store) Epoch() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// Events returns the audit events recorded so far.
func (s *Store) Events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

// RunOf returns a run as stored (to see the grant delegation bound).
func (s *Store) RunOf(id ids.UUID) app.Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs[id]
}

// Put stores a grant revision directly, bypassing every check, as a
// database write around the use cases would (HR-046 tests).
func (s *Store) Put(g domain.Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[g.ID] = append(s.grants[g.ID], g)
}

func (s *Store) checkOrg(org ids.OrgID) error {
	if org != s.Org {
		return app.ErrNotFound
	}
	return nil
}

func (s *Store) current(id domain.GrantID) (domain.Grant, bool) {
	revs := s.grants[id]
	if len(revs) == 0 {
		return domain.Grant{}, false
	}
	return revs[len(revs)-1], true
}

// Agent implements app.Subjects.
func (s *Store) Agent(_ context.Context, org ids.OrgID, id ids.UUID) (app.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if s.checkOrg(org) != nil || !ok {
		return app.Agent{}, app.ErrNotFound
	}
	return a, nil
}

// Run implements app.Subjects.
func (s *Store) Run(_ context.Context, org ids.OrgID, id ids.UUID) (app.Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[id]
	if s.checkOrg(org) != nil || !ok {
		return app.Run{}, app.ErrNotFound
	}
	return r, nil
}

// PrincipalActive implements app.Subjects.
func (s *Store) PrincipalActive(_ context.Context, org ids.OrgID, p domain.Principal) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.checkOrg(org) == nil && s.principals[p], nil
}

// ScopePath implements app.Subjects: every scope is checked at the org.
func (s *Store) ScopePath(_ context.Context, org ids.OrgID, _ domain.Scope) (tdomain.Path, error) {
	return tdomain.OrgPath(org), nil
}

// Active implements app.Definitions.
func (s *Store) Active(_ context.Context, _ ids.OrgID, op string) (*defs.Definition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.defs[op], nil
}

// Grant implements app.Repository.
func (s *Store) Grant(_ context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.current(id)
	if s.checkOrg(org) != nil || !ok {
		return domain.Grant{}, app.ErrNotFound
	}
	return g, nil
}

// Chain implements app.Repository.
func (s *Store) Chain(_ context.Context, org ids.OrgID, id domain.GrantID) ([]domain.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return nil, err
	}
	var out []domain.Grant
	for cur := id; !cur.IsZero(); {
		g, ok := s.current(cur)
		if !ok {
			return nil, app.ErrNotFound
		}
		out = append(out, g)
		cur = g.Parent
	}
	slices.Reverse(out)
	return out, nil
}

// Envelopes implements app.Repository.
func (s *Store) Envelopes(_ context.Context, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return nil, err
	}
	var out []domain.Envelope
	for _, sc := range scopes {
		if e, ok := s.envelopes[scopeKey(sc)]; ok {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Store) childCounts(id domain.GrantID, now time.Time) (active, total int) {
	for _, revs := range s.grants {
		g := revs[len(revs)-1]
		if g.Parent != id {
			continue
		}
		total++
		if g.State == domain.StateActive && now.Before(g.ExpiresAt) {
			active++
		}
	}
	return active, total
}

// ChildCounts implements app.Repository.
func (s *Store) ChildCounts(_ context.Context, org ids.OrgID, id domain.GrantID, now time.Time) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return 0, 0, err
	}
	a, t := s.childCounts(id, now)
	return a, t, nil
}

// Issue implements app.Repository.
func (s *Store) Issue(_ context.Context, org ids.OrgID, g domain.Grant, ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return err
	}
	if _, exists := s.grants[g.ID]; exists {
		return app.ErrConflict
	}
	s.grants[g.ID] = []domain.Grant{g}
	s.events = append(s.events, ev)
	return nil
}

// Delegate implements app.Repository: the parent check, the fan-out count,
// the insert and the run binding happen under one lock, like the database
// transaction that locks the parent's row.
func (s *Store) Delegate(_ context.Context, org ids.OrgID, child domain.Grant, parentRevision int, childRun ids.UUID, f app.Fanout, ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return err
	}
	parent, ok := s.current(child.Parent)
	if !ok || parent.Revision != parentRevision || parent.State != domain.StateActive {
		return app.ErrConflict
	}
	active, total := s.childCounts(parent.ID, child.NotBefore)
	if active >= f.MaxActive || total >= f.MaxTotal {
		return fmt.Errorf("%w: the parent grant has no room for another child", domain.ErrOutside)
	}
	run, ok := s.runs[childRun]
	if !ok || !run.GrantID.IsZero() {
		return app.ErrConflict
	}
	run.GrantID = child.ID
	s.runs[childRun] = run
	s.grants[child.ID] = []domain.Grant{child}
	s.events = append(s.events, ev)
	return nil
}

// Revise implements app.Repository.
func (s *Store) Revise(_ context.Context, org ids.OrgID, next domain.Grant, _ bool, _ ids.UUID, ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return err
	}
	cur, ok := s.current(next.ID)
	if !ok || cur.Revision != next.Revision-1 || cur.State != domain.StateActive {
		return app.ErrConflict
	}
	s.epoch++
	s.grants[next.ID] = append(s.grants[next.ID], next)
	s.events = append(s.events, ev)
	return nil
}

// Revoke implements app.Repository.
func (s *Store) Revoke(_ context.Context, org ids.OrgID, id domain.GrantID, ev audit.Event) ([]domain.GrantID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return nil, err
	}
	if _, ok := s.current(id); !ok {
		return nil, app.ErrNotFound
	}
	s.epoch++
	var revoked []domain.GrantID
	queue := []domain.GrantID{id}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		revs := s.grants[cur]
		if g := revs[len(revs)-1]; g.State == domain.StateActive {
			revs[len(revs)-1].State = domain.StateRevoked
			revoked = append(revoked, cur)
		}
		for cid, crevs := range s.grants {
			if crevs[len(crevs)-1].Parent == cur {
				queue = append(queue, cid)
			}
		}
	}
	s.events = append(s.events, ev)
	return revoked, nil
}

// PutEnvelope implements app.Repository.
func (s *Store) PutEnvelope(_ context.Context, org ids.OrgID, e domain.Envelope, _ bool, ev audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkOrg(org); err != nil {
		return err
	}
	cur := s.envelopes[scopeKey(e.Scope)]
	if cur.Revision != e.Revision-1 {
		return app.ErrConflict
	}
	s.epoch++
	s.envelopes[scopeKey(e.Scope)] = e
	s.events = append(s.events, ev)
	return nil
}
