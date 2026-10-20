// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrDelegateTxUnavailable: the store cannot delegate in the caller's
// transaction.
var ErrDelegateTxUnavailable = errors.New("grants: delegation in a caller's transaction is not available")

// DelegateTxStore is the repository's in-transaction side for delegation
// (G0 M14 D89): the Authority delegates a requester's grant to a peer
// agent's child run inside BeginDispatch's transaction.
type DelegateTxStore interface {
	RunInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Run, error)
	AgentInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (Agent, error)
	GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID) (domain.Grant, bool, error)
	EnvelopesInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error)
	ChildCountsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID, now time.Time) (active, total int, err error)
	DelegateInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, child *domain.Grant, parentRevision int, childRun ids.UUID, f Fanout, ev audit.Event) error
}

// DelegateTx is Delegate inside the caller's transaction: the same checks
// against the parent grant, the guardrails, the depth and the fan-out
// (under the parent's row lock), and the lifetime, with every read and
// write in tx.
func (s *Service) DelegateTx(ctx context.Context, tx db.TenantTx, w Workload, req DelegateRequest) (domain.Grant, error) {
	st, ok := s.Store.(DelegateTxStore)
	if !ok || w.Org != tx.OrgID() {
		return domain.Grant{}, ErrDelegateTxUnavailable
	}
	return s.delegateWith(ctx, txDelegation{st: st, tx: tx}, w, req)
}

// delegation is where Delegate reads and writes.
type delegation interface {
	run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error)
	grant(ctx context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error)
	agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error)
	envelopes(ctx context.Context, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error)
	childCounts(ctx context.Context, org ids.OrgID, id domain.GrantID, now time.Time) (int, int, error)
	delegate(ctx context.Context, org ids.OrgID, child *domain.Grant, parentRevision int, childRun ids.UUID, f Fanout, ev audit.Event) error
}

// repoDelegation is the repository, each call its own transaction.
type repoDelegation struct{ s *Service }

func (d repoDelegation) run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error) {
	return d.s.run(ctx, org, id)
}

func (d repoDelegation) grant(ctx context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error) {
	return d.s.grant(ctx, org, id)
}

func (d repoDelegation) agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error) {
	return d.s.agent(ctx, org, id)
}

func (d repoDelegation) envelopes(ctx context.Context, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error) {
	return d.s.Repo.Envelopes(ctx, org, scopes)
}

func (d repoDelegation) childCounts(ctx context.Context, org ids.OrgID, id domain.GrantID, now time.Time) (int, int, error) {
	return d.s.Repo.ChildCounts(ctx, org, id, now)
}

func (d repoDelegation) delegate(ctx context.Context, org ids.OrgID, child *domain.Grant, rev int, run ids.UUID, f Fanout, ev audit.Event) error {
	return d.s.Repo.Delegate(ctx, org, child, rev, run, f, ev)
}

// txDelegation is the caller's transaction.
type txDelegation struct {
	st DelegateTxStore
	tx db.TenantTx
}

func (d txDelegation) run(ctx context.Context, org ids.OrgID, id ids.UUID) (Run, error) {
	r, err := d.st.RunInTx(ctx, d.tx, org, id)
	if errors.Is(err, ErrNotFound) {
		return Run{}, ErrRunNotFound
	}
	return r, err
}

func (d txDelegation) grant(ctx context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error) {
	g, found, err := d.st.GrantInTx(ctx, d.tx, org, id)
	if err == nil && !found {
		return domain.Grant{}, ErrGrantNotFound
	}
	return g, err
}

func (d txDelegation) agent(ctx context.Context, org ids.OrgID, id ids.UUID) (Agent, error) {
	a, err := d.st.AgentInTx(ctx, d.tx, org, id)
	if errors.Is(err, ErrNotFound) {
		return Agent{}, ErrAgentNotFound
	}
	return a, err
}

func (d txDelegation) envelopes(ctx context.Context, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error) {
	return d.st.EnvelopesInTx(ctx, d.tx, org, scopes)
}

func (d txDelegation) childCounts(ctx context.Context, org ids.OrgID, id domain.GrantID, now time.Time) (int, int, error) {
	return d.st.ChildCountsInTx(ctx, d.tx, org, id, now)
}

func (d txDelegation) delegate(ctx context.Context, org ids.OrgID, child *domain.Grant, rev int, run ids.UUID, f Fanout, ev audit.Event) error {
	return d.st.DelegateInTx(ctx, d.tx, org, child, rev, run, f, ev)
}
