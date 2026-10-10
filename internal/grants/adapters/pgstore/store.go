// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgstore stores grants and guardrails in PostgreSQL and reads the
// agents, runs and principals they bind (G0 M4 part 2): the grants/app
// Repository and Subjects ports, and the chain and guardrail reads of the
// decision pipeline.
//
// Lock order (design decision 8): every removal of authority (revision,
// revocation, guardrail change) raises the org containment epoch as its
// first statement, which locks the containment row; delegation takes that
// row FOR SHARE first and reads the parent only after it. So a delegation
// either commits before a revocation starts, and is revoked with its
// parent, or sees the parent revoked.
package pgstore

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// Store implements app.Repository and app.Subjects.
type Store struct {
	Pool *db.Pool
}

var (
	_ app.Repository = (*Store)(nil)
	_ app.Subjects   = (*Store)(nil)
	_ app.Listing    = (*Store)(nil)
)

// ScopeKey names an envelope scope as stored.
func ScopeKey(s domain.Scope) string {
	switch s.Kind {
	case domain.ScopeOrg:
		return "org"
	case domain.ScopePrincipal:
		return string(s.Principal.Kind) + ":" + s.Principal.ID.String()
	case domain.ScopeBusinessUnit, domain.ScopeTeam, domain.ScopeEnvironment:
	}
	return string(s.Kind) + ":" + s.ID.String()
}

func parseScope(kind, key string) (domain.Scope, error) {
	s := domain.Scope{Kind: domain.ScopeKind(kind)}
	if s.Kind == domain.ScopeOrg {
		return s, nil
	}
	k, v, ok := strings.Cut(key, ":")
	id, err := ids.ParseUUID(v)
	if !ok || err != nil {
		return s, fmt.Errorf("grants: stored scope %q", key)
	}
	if s.Kind == domain.ScopePrincipal {
		s.Principal = domain.Principal{Kind: domain.PrincipalKind(k), ID: id}
	} else {
		s.ID = id
	}
	return s, nil
}

func principalCols(p domain.Principal) (user, sa *ids.UUID) {
	id := p.ID
	if p.Kind == domain.PrincipalServiceAccount {
		return nil, &id
	}
	return &id, nil
}

func principalOf(user, sa *ids.UUID) domain.Principal {
	if sa != nil {
		return domain.Principal{Kind: domain.PrincipalServiceAccount, ID: *sa}
	}
	if user != nil {
		return domain.Principal{Kind: domain.PrincipalUser, ID: *user}
	}
	return domain.Principal{}
}

func optUUID(u ids.UUID) *ids.UUID {
	if u.IsZero() {
		return nil
	}
	return &u
}

// grantRow is the shape of GetGrant and GetGrantChain rows.
type grantRow struct {
	ID, AgentID, EnvironmentID, GrantorID       ids.UUID
	InstanceID, PrincipalUserID, PrincipalSaID  *ids.UUID
	ParentID                                    *ids.UUID
	Depth, DelegationDepth, MaxChildren, MinAtt int16
	State, GrantorKind, Basis, TaskRef          string
	CurrentRevision                             int32
	NotBefore, ExpiresAt                        time.Time
	Bounds, Requirements, Limits                []byte
	RevisedAt                                   time.Time
}

func toGrant(org ids.OrgID, r grantRow) (domain.Grant, error) {
	b, err := domain.DecodeBounds(r.Bounds)
	if err != nil {
		return domain.Grant{}, fmt.Errorf("grants: stored bounds: %w", err)
	}
	var reqs []domain.Requirement
	if err := json.Unmarshal(r.Requirements, &reqs, json.RejectUnknownMembers(true)); err != nil {
		return domain.Grant{}, fmt.Errorf("grants: stored requirements: %w", err)
	}
	lim, err := domain.DecodeLimits(r.Limits)
	if err != nil {
		return domain.Grant{}, fmt.Errorf("grants: stored limits: %w", err)
	}
	g := domain.Grant{
		Org: org, Revision: int(r.CurrentRevision), State: domain.State(r.State),
		AgentID: r.AgentID, Principal: principalOf(r.PrincipalUserID, r.PrincipalSaID), EnvironmentID: r.EnvironmentID,
		TaskRef: r.TaskRef, NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, Bounds: b, Requirements: reqs, Limits: lim,
		Delegation:     domain.Delegation{Depth: int(r.DelegationDepth), MaxChildren: int(r.MaxChildren)},
		MinAttestation: int(r.MinAtt), Depth: int(r.Depth),
		Grantor: domain.Principal{Kind: domain.PrincipalKind(r.GrantorKind), ID: r.GrantorID}, Basis: r.Basis,
		RevisedAt: r.RevisedAt,
	}
	if g.ID, err = domain.ParseGrantID(r.ID.String()); err != nil {
		return domain.Grant{}, err
	}
	if r.InstanceID != nil {
		g.InstanceID = *r.InstanceID
	}
	if r.ParentID != nil {
		if g.Parent, err = domain.ParseGrantID(r.ParentID.String()); err != nil {
			return domain.Grant{}, err
		}
	}
	return g, nil
}

func fromGetGrant(r dbq.GetGrantRow) grantRow {
	return grantRow{
		r.ID, r.AgentID, r.EnvironmentID, r.GrantorID, r.InstanceID, r.PrincipalUserID, r.PrincipalSaID, r.ParentID,
		r.Depth, r.DelegationDepth, r.MaxChildren, r.MinAttestation, r.State, r.GrantorKind, r.Basis, r.TaskRef,
		r.CurrentRevision, r.NotBefore, r.ExpiresAt, r.Bounds, r.Requirements, r.Limits, r.CreatedAt,
	}
}

func fromChain(r dbq.GetGrantChainRow) grantRow {
	return grantRow{
		r.ID, r.AgentID, r.EnvironmentID, r.GrantorID, r.InstanceID, r.PrincipalUserID, r.PrincipalSaID, r.ParentID,
		r.Depth, r.DelegationDepth, r.MaxChildren, r.MinAttestation, r.State, r.GrantorKind, r.Basis, r.TaskRef,
		r.CurrentRevision, r.NotBefore, r.ExpiresAt, r.Bounds, r.Requirements, r.Limits, r.CreatedAt,
	}
}

// Grant implements app.Repository.
func (s *Store) Grant(ctx context.Context, org ids.OrgID, id domain.GrantID) (domain.Grant, error) {
	var g domain.Grant
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetGrant(ctx, org, id.UUID())
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		g, err = toGrant(org, fromGetGrant(row))
		return err
	})
	return g, err
}

// Chain implements app.Repository: the grant and its ancestors, root first.
func (s *Store) Chain(ctx context.Context, org ids.OrgID, id domain.GrantID) ([]domain.Grant, error) {
	var out []domain.Grant
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.ChainInTx(ctx, tx, org, id)
		return err
	})
	return out, err
}

// ChainInTx is Chain inside the caller's transaction (the Authority's
// one-snapshot read).
func (s *Store) ChainInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID) ([]domain.Grant, error) {
	rows, err := dbq.New(tx).GetGrantChain(ctx, org, id.UUID())
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, app.ErrNotFound
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, r := range rows {
		g, err := toGrant(org, fromChain(r))
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// Envelopes implements app.Repository.
func (s *Store) Envelopes(ctx context.Context, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error) {
	var out []domain.Envelope
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.EnvelopesInTx(ctx, tx, org, scopes)
		return err
	})
	return out, err
}

// EnvelopesInTx is Envelopes inside the caller's transaction.
func (s *Store) EnvelopesInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, scopes []domain.Scope) ([]domain.Envelope, error) {
	keys := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		keys = append(keys, ScopeKey(sc))
	}
	rows, err := dbq.New(tx).GetEnvelopes(ctx, org, keys)
	if err != nil {
		return nil, err
	}
	var out []domain.Envelope
	for _, r := range rows {
		e, err := toEnvelope(org, envelopeRow(r))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// EnvelopeByID implements app.Repository: revision 0 is the current one.
func (s *Store) EnvelopeByID(ctx context.Context, org ids.OrgID, id domain.EnvelopeID, revision int) (domain.Envelope, error) {
	var out domain.Envelope
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetEnvelopeRevision(ctx, org, id.UUID(), int32(revision)) //nolint:gosec // validated
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = toEnvelope(org, envelopeRow(r))
		return err
	}, db.ReadOnly())
	return out, err
}

// ListEnvelopes implements app.Repository: current revisions, oldest
// first, optionally of one scope kind.
func (s *Store) ListEnvelopes(ctx context.Context, org ids.OrgID, after ids.UUID, limit int32, kind domain.ScopeKind) ([]domain.Envelope, error) {
	var out []domain.Envelope
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListEnvelopes(ctx, dbq.ListEnvelopesParams{
			OrgID: org, After: optUUID(after), ScopeKind: string(kind), PageLimit: limit,
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			e, err := toEnvelope(org, envelopeRow(r))
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// ListGrants implements app.Repository: newest first.
func (s *Store) ListGrants(ctx context.Context, org ids.OrgID, f app.GrantFilter, before ids.UUID, limit int32) ([]domain.Grant, error) {
	var out []domain.Grant
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		p := dbq.ListGrantsParams{OrgID: org, Before: optUUID(before), AgentID: f.AgentID, State: string(f.State), PageLimit: limit}
		if !f.Parent.IsZero() {
			parent := f.Parent.UUID()
			p.ParentID = &parent
		}
		rows, err := dbq.New(tx).ListGrants(ctx, p)
		if err != nil {
			return err
		}
		for _, r := range rows {
			g, err := toGrant(org, grantRow{
				r.ID, r.AgentID, r.EnvironmentID, r.GrantorID, r.InstanceID, r.PrincipalUserID, r.PrincipalSaID, r.ParentID,
				r.Depth, r.DelegationDepth, r.MaxChildren, r.MinAttestation, r.State, r.GrantorKind, r.Basis, r.TaskRef,
				r.CurrentRevision, r.NotBefore, r.ExpiresAt, r.Bounds, r.Requirements, r.Limits, r.CreatedAt,
			})
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// BudgetAccounts implements app.Repository: the latest period of every
// budget account the owners hold.
func (s *Store) BudgetAccounts(ctx context.Context, org ids.OrgID, owners []ids.UUID) ([]app.BudgetAccount, error) {
	var out []app.BudgetAccount
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListOwnerBudgetAccounts(ctx, org, owners)
		if err != nil {
			return err
		}
		for _, r := range rows {
			a := app.BudgetAccount{
				OwnerKind: r.OwnerKind, OwnerID: r.OwnerID, Rule: r.Rule, PeriodStart: r.PeriodStart, Rank: int(r.Rank),
				Reserved: r.Reserved, Spent: r.Spent, ReservedCount: int64(r.ReservedCount), SpentCount: int64(r.SpentCount),
			}
			if r.Currency != nil {
				a.Currency = *r.Currency
			}
			out = append(out, a)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// envelopeRow is the shape of every guardrail read.
type envelopeRow struct {
	ID                              ids.UUID
	ScopeKind, ScopeKey             string
	Revision                        int32
	Name                            string
	Bounds, Requirements, Limits    []byte
	MaxDepth, MaxChildren           pgtype.Int2
	MaxRootLifetimeS, RepeatWindowS pgtype.Int8
	MinAttestation                  int16
	CreatedBy                       string
	CreatedAt                       time.Time
}

func toEnvelope(org ids.OrgID, r envelopeRow) (domain.Envelope, error) {
	scope, err := parseScope(r.ScopeKind, r.ScopeKey)
	if err != nil {
		return domain.Envelope{}, err
	}
	b, err := domain.DecodeBounds(r.Bounds)
	if err != nil {
		return domain.Envelope{}, fmt.Errorf("grants: stored guardrail bounds: %w", err)
	}
	var reqs []domain.Requirement
	if err := json.Unmarshal(r.Requirements, &reqs, json.RejectUnknownMembers(true)); err != nil {
		return domain.Envelope{}, fmt.Errorf("grants: stored guardrail requirements: %w", err)
	}
	lim, err := domain.DecodeLimits(r.Limits)
	if err != nil {
		return domain.Envelope{}, fmt.Errorf("grants: stored guardrail limits: %w", err)
	}
	id, err := domain.ParseEnvelopeID(r.ID.String())
	if err != nil {
		return domain.Envelope{}, err
	}
	e := domain.Envelope{
		ID: id, Org: org, Revision: int(r.Revision), Scope: scope, Name: r.Name, Bounds: b,
		Requirements: reqs, Limits: lim, MinAttestation: int(r.MinAttestation), ChangedBy: r.CreatedBy, RevisedAt: r.CreatedAt,
	}
	if r.MaxDepth.Valid {
		v := int(r.MaxDepth.Int16)
		e.Settings.MaxDepth = &v
	}
	if r.MaxChildren.Valid {
		v := int(r.MaxChildren.Int16)
		e.Settings.MaxChildren = &v
	}
	if r.MaxRootLifetimeS.Valid {
		v := time.Duration(r.MaxRootLifetimeS.Int64) * time.Second
		e.Settings.MaxRootLifetime = &v
	}
	if r.RepeatWindowS.Valid {
		v := time.Duration(r.RepeatWindowS.Int64) * time.Second
		e.Settings.RepeatWindow = &v
	}
	return e, nil
}

// ChildCounts implements app.Repository.
func (s *Store) ChildCounts(ctx context.Context, org ids.OrgID, id domain.GrantID, now time.Time) (int, int, error) {
	var active, total int32
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		parent := id.UUID()
		var err error
		if active, err = q.CountActiveChildren(ctx, org, &parent, now); err != nil {
			return err
		}
		total, err = q.GetChildrenTotal(ctx, org, parent)
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		return err
	})
	return int(active), int(total), err
}

type encoded struct{ bounds, requirements, limits []byte }

func encode(b domain.Bounds, reqs []domain.Requirement, lim domain.Limits) (encoded, error) {
	var e encoded
	var err error
	if e.bounds, err = domain.EncodeBounds(b); err != nil {
		return e, err
	}
	if reqs == nil {
		reqs = []domain.Requirement{}
	}
	if e.requirements, err = json.Marshal(reqs, json.Deterministic(true)); err != nil {
		return e, err
	}
	e.limits, err = json.Marshal(lim, json.Deterministic(true))
	return e, err
}

func insertGrant(ctx context.Context, q *dbq.Queries, org ids.OrgID, g domain.Grant, widens bool, createdBy string) error {
	enc, err := encode(g.Bounds, g.Requirements, g.Limits)
	if err != nil {
		return err
	}
	user, sa := principalCols(g.Principal)
	if g.Revision == 1 {
		var parent *ids.UUID
		if !g.Parent.IsZero() {
			p := g.Parent.UUID()
			parent = &p
		}
		if err := q.InsertGrant(ctx, dbq.InsertGrantParams{
			OrgID: org, ID: g.ID.UUID(), AgentID: g.AgentID, InstanceID: optUUID(g.InstanceID), PrincipalUserID: user,
			PrincipalSaID: sa, EnvironmentID: g.EnvironmentID, ParentID: parent, Depth: int16(g.Depth), //nolint:gosec // 0..4
			CurrentRevision: 1, GrantorKind: string(g.Grantor.Kind), GrantorID: g.Grantor.ID, Basis: g.Basis,
		}); err != nil {
			return err
		}
	}
	return q.InsertGrantRevision(ctx, dbq.InsertGrantRevisionParams{
		OrgID: org, ID: ids.NewV7(), GrantID: g.ID.UUID(), Revision: int32(g.Revision), TaskRef: g.TaskRef, //nolint:gosec // small
		NotBefore: g.NotBefore, ExpiresAt: g.ExpiresAt, Bounds: enc.bounds, Requirements: enc.requirements, Limits: enc.limits,
		DelegationDepth: int16(g.Delegation.Depth), MaxChildren: int16(g.Delegation.MaxChildren), //nolint:gosec // validated
		MinAttestation: int16(g.MinAttestation), Widens: widens, CreatedBy: createdBy, //nolint:gosec // 0..2
	})
}

func actorString(ev audit.Event) string { return ev.Actor.Type + ":" + ev.Actor.ID }

// Issue implements app.Repository.
func (s *Store) Issue(ctx context.Context, org ids.OrgID, g domain.Grant, ev audit.Event) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := insertGrant(ctx, q, org, g, false, actorString(ev)); err != nil {
			return err
		}
		if err := q.InsertGrantLineageSelf(ctx, org, g.ID.UUID()); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
}

// Delegate implements app.Repository.
func (s *Store) Delegate(ctx context.Context, org ids.OrgID, child domain.Grant, parentRevision int, childRun ids.UUID, f app.Fanout, ev audit.Event) error {
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.ShareContainment(ctx, org); err != nil {
			return fmt.Errorf("grants: containment: %w", err)
		}
		parent := child.Parent.UUID()
		lock, err := q.LockGrant(ctx, org, parent)
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		if lock.State != string(domain.StateActive) || int(lock.CurrentRevision) != parentRevision {
			return app.ErrConflict
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		active, err := q.CountActiveChildren(ctx, org, &parent, now)
		if err != nil {
			return err
		}
		if int(active) >= f.MaxActive {
			return fmt.Errorf("%w: the parent grant already has %d active children", domain.ErrOutside, active)
		}
		if err := db.ExpectOneRow(q.IncrementGrantChildren(ctx, org, parent, int32(f.MaxTotal))); err != nil { //nolint:gosec // 100
			return fmt.Errorf("%w: the parent grant has delegated the most a grant may", domain.ErrOutside)
		}
		if err := insertGrant(ctx, q, org, child, false, actorString(ev)); err != nil {
			return err
		}
		if err := q.InsertGrantLineageFromParent(ctx, child.ID.UUID(), org, parent); err != nil {
			return err
		}
		if err := q.InsertGrantLineageSelf(ctx, org, child.ID.UUID()); err != nil {
			return err
		}
		gid := child.ID.UUID()
		if err := db.ExpectOneRow(q.BindChildRunGrant(ctx, &gid, org, childRun)); err != nil {
			return app.ErrConflict
		}
		_, err = audit.Record(ctx, tx, ev)
		return err
	})
	if db.IsUniqueViolation(err) {
		return app.ErrConflict
	}
	return err
}

// Revise implements app.Repository: the containment epoch first, then the
// conditional revision advance, and the access request it answers.
func (s *Store) Revise(ctx context.Context, org ids.OrgID, next domain.Grant, widens bool, accessRequest ids.UUID, ev audit.Event) error {
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := db.ExpectOneRow(q.RaiseContainmentEpoch(ctx, org)); err != nil {
			return fmt.Errorf("grants: containment epoch: %w", err)
		}
		if err := db.ExpectOneRow(q.AdvanceGrantRevision(ctx, dbq.AdvanceGrantRevisionParams{
			NextRevision: int32(next.Revision), OrgID: org, ID: next.ID.UUID(), PrevRevision: int32(next.Revision - 1), //nolint:gosec // small
		})); err != nil {
			return app.ErrConflict
		}
		if err := insertGrant(ctx, q, org, next, widens, actorString(ev)); err != nil {
			return err
		}
		if !accessRequest.IsZero() {
			err := pgwaitlist.SettleAccessRequest(ctx, tx, org, accessRequest, next.ID.UUID(), actorString(ev), next.Revision)
			if errors.Is(err, pgwaitlist.ErrAccessRequestNotOpen) {
				return app.ErrAccessRequestNotOpen
			} else if err != nil {
				return err
			}
		}
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
	if db.IsUniqueViolation(err) {
		return app.ErrConflict
	}
	return err
}

// Revoke implements app.Repository: the containment epoch first, then the
// grant and every descendant in one statement (HR-047).
func (s *Store) Revoke(ctx context.Context, org ids.OrgID, id domain.GrantID, ev audit.Event) ([]domain.GrantID, error) {
	var out []domain.GrantID
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := db.ExpectOneRow(q.RaiseContainmentEpoch(ctx, org)); err != nil {
			return fmt.Errorf("grants: containment epoch: %w", err)
		}
		if _, err := q.GetGrant(ctx, org, id.UUID()); db.IsNoRows(err) {
			return app.ErrNotFound
		} else if err != nil {
			return err
		}
		reason := ev.Details["reason"]
		if reason == "" {
			reason = "revoked"
		}
		revoked, err := q.RevokeGrantTree(ctx, &reason, org, id.UUID())
		if err != nil {
			return err
		}
		for _, r := range revoked {
			g, err := domain.ParseGrantID(r.String())
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		if ev.Details != nil {
			ev.Details["revoked"] = strconv.Itoa(len(out))
		}
		_, err = audit.Record(ctx, tx, ev)
		return err
	})
	return out, err
}

// PutEnvelope implements app.Repository: the containment epoch first, then
// the conditional head update and the new revision.
func (s *Store) PutEnvelope(ctx context.Context, org ids.OrgID, e domain.Envelope, widens bool, ev audit.Event) error {
	enc, err := encode(e.Bounds, e.Requirements, e.Limits)
	if err != nil {
		return err
	}
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := db.ExpectOneRow(q.RaiseContainmentEpoch(ctx, org)); err != nil {
			return fmt.Errorf("grants: containment epoch: %w", err)
		}
		key := ScopeKey(e.Scope)
		head, err := q.GetEnvelopeHead(ctx, org, key)
		switch {
		case db.IsNoRows(err):
			if e.Revision != 1 {
				return app.ErrConflict
			}
			if err := q.InsertEnvelope(ctx, dbq.InsertEnvelopeParams{OrgID: org, ID: e.ID.UUID(), ScopeKind: string(e.Scope.Kind), ScopeKey: key}); err != nil {
				return err
			}
		case err != nil:
			return err
		case head.ID != e.ID.UUID():
			return app.ErrConflict
		default:
			if err := db.ExpectOneRow(q.AdvanceEnvelopeRevision(ctx, dbq.AdvanceEnvelopeRevisionParams{
				NextRevision: int32(e.Revision), OrgID: org, ID: head.ID, PrevRevision: int32(e.Revision - 1), //nolint:gosec // small
			})); err != nil {
				return app.ErrConflict
			}
		}
		p := dbq.InsertEnvelopeRevisionParams{
			OrgID: org, ID: ids.NewV7(), EnvelopeID: e.ID.UUID(), Revision: int32(e.Revision), Name: e.Name, //nolint:gosec // small
			Bounds: enc.bounds, Requirements: enc.requirements, Limits: enc.limits,
			MinAttestation: int16(e.MinAttestation), Widens: widens, CreatedBy: actorString(ev), //nolint:gosec // 0..2
		}
		if v := e.Settings.MaxDepth; v != nil {
			p.MaxDepth = pgtype.Int2{Int16: int16(*v), Valid: true} //nolint:gosec // validated
		}
		if v := e.Settings.MaxChildren; v != nil {
			p.MaxChildren = pgtype.Int2{Int16: int16(*v), Valid: true} //nolint:gosec // validated
		}
		if v := e.Settings.MaxRootLifetime; v != nil {
			p.MaxRootLifetimeS = pgtype.Int8{Int64: int64(*v / time.Second), Valid: true}
		}
		if v := e.Settings.RepeatWindow; v != nil {
			p.RepeatWindowS = pgtype.Int8{Int64: int64(*v / time.Second), Valid: true}
		}
		if err := q.InsertEnvelopeRevision(ctx, p); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, ev)
		return err
	})
	if db.IsUniqueViolation(err) {
		return app.ErrConflict
	}
	return err
}

// Agent implements app.Subjects.
func (s *Store) Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (app.Agent, error) {
	var out app.Agent
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.AgentInTx(ctx, tx, org, id)
		return err
	})
	return out, err
}

// AgentInTx is Agent inside the caller's transaction (the Authority's
// one-snapshot read).
func (s *Store) AgentInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID) (app.Agent, error) {
	row, err := dbq.New(tx).SubjectAgent(ctx, org, id)
	if db.IsNoRows(err) {
		return app.Agent{}, app.ErrNotFound
	}
	if err != nil {
		return app.Agent{}, err
	}
	out := app.Agent{ID: id, State: row.State, Path: tdomain.OrgPath(org)}
	if row.TeamID != nil {
		out.TeamID = *row.TeamID
		if row.BusinessUnitID != nil {
			out.BusinessUnitID = *row.BusinessUnitID
			out.Path = out.Path.Child(tdomain.ScopeBusinessUnit, *row.BusinessUnitID)
		}
		out.Path = out.Path.Child(tdomain.ScopeTeam, *row.TeamID)
	}
	if row.EnvironmentID != nil {
		out.EnvironmentID = *row.EnvironmentID
	}
	return out, nil
}

// Run implements app.Subjects.
func (s *Store) Run(ctx context.Context, org ids.OrgID, id ids.UUID) (app.Run, error) {
	var out app.Run
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).SubjectRun(ctx, org, id)
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		out = app.Run{
			ID: id, AgentID: row.AgentID, Principal: principalOf(row.PrincipalUserID, row.PrincipalSaID),
			EnvironmentID: row.EnvironmentID, Active: row.Live, ExpiresAt: row.ExpiresAt,
		}
		if row.InstanceID != nil {
			out.InstanceID = *row.InstanceID
		}
		if row.ParentRunID != nil {
			out.ParentRunID = *row.ParentRunID
		}
		if row.GrantID != nil {
			out.GrantID, err = domain.ParseGrantID(row.GrantID.String())
		}
		return err
	})
	return out, err
}

// PrincipalActive implements app.Subjects.
func (s *Store) PrincipalActive(ctx context.Context, org ids.OrgID, p domain.Principal) (bool, error) {
	var active bool
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		switch p.Kind {
		case domain.PrincipalUser:
			active, err = q.SubjectUserActive(ctx, org, p.ID)
		case domain.PrincipalServiceAccount:
			active, err = q.SubjectServiceAccountActive(ctx, org, p.ID)
		case domain.PrincipalInstance:
		}
		if db.IsNoRows(err) {
			active, err = false, nil
		}
		return err
	})
	return active, err
}

// ScopePath implements app.Subjects: where guardrail permissions for a
// scope are checked. Principal guardrails are managed at the org.
func (s *Store) ScopePath(ctx context.Context, org ids.OrgID, sc domain.Scope) (tdomain.Path, error) {
	var out tdomain.Path
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		teamPath := func(id ids.UUID) (tdomain.Path, error) {
			t, err := q.GetTeam(ctx, org, id)
			if err != nil {
				return nil, err
			}
			p := tdomain.OrgPath(org)
			if t.BusinessUnitID != nil {
				p = p.Child(tdomain.ScopeBusinessUnit, *t.BusinessUnitID)
			}
			return p.Child(tdomain.ScopeTeam, t.ID), nil
		}
		var err error
		switch sc.Kind {
		case domain.ScopeOrg, domain.ScopePrincipal:
			out = tdomain.OrgPath(org)
		case domain.ScopeBusinessUnit:
			if _, err = q.GetBusinessUnit(ctx, org, sc.ID); err == nil {
				out = tdomain.OrgPath(org).Child(tdomain.ScopeBusinessUnit, sc.ID)
			}
		case domain.ScopeTeam:
			out, err = teamPath(sc.ID)
		case domain.ScopeEnvironment:
			var e dbq.PcEnvironment
			if e, err = q.GetEnvironment(ctx, org, sc.ID); err == nil {
				out = tdomain.OrgPath(org)
				if e.TeamID != nil {
					out, err = teamPath(*e.TeamID)
				}
				out = out.Child(tdomain.ScopeEnvironment, e.ID)
			}
		}
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		return err
	})
	return out, err
}

// GrantInTx returns a grant's current revision inside the caller's
// transaction (runs/app Grants: binding a run at StartRun).
func (s *Store) GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID) (domain.Grant, bool, error) {
	row, err := dbq.New(tx).GetGrant(ctx, org, id.UUID())
	if db.IsNoRows(err) {
		return domain.Grant{}, false, nil
	}
	if err != nil {
		return domain.Grant{}, false, err
	}
	g, err := toGrant(org, fromGetGrant(row))
	return g, err == nil, err
}
