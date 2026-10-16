// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgstore

import (
	"context"
	"fmt"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The in-transaction writes of automation issuance (G0 M11 part 2 D9):
// they run in the engine's transaction, never in one of their own.

var _ app.TxStore = (*Store)(nil)

// ReadTx implements app.TxStore.
func (s *Store) ReadTx(ctx context.Context, org ids.OrgID, fn func(ctx context.Context, tx db.TenantTx) error) error {
	return s.Pool.InTenantTx(ctx, org, fn, db.ReadOnly())
}

// PrincipalActiveInTx implements app.TxStore.
func (s *Store) PrincipalActiveInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, p domain.Principal) (bool, error) {
	q := dbq.New(tx)
	var active bool
	var err error
	switch p.Kind {
	case domain.PrincipalUser:
		active, err = q.SubjectUserActive(ctx, org, p.ID)
	case domain.PrincipalServiceAccount:
		active, err = q.SubjectServiceAccountActive(ctx, org, p.ID)
	case domain.PrincipalInstance:
	}
	if db.IsNoRows(err) {
		return false, nil
	}
	return active, err
}

// IssueInTx implements app.TxStore: the grant, its lineage and its audit
// record in tx.
func (s *Store) IssueInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, g domain.Grant, ev audit.Event) error {
	q := dbq.New(tx)
	if err := insertGrant(ctx, q, org, g, false, actorString(ev)); err != nil {
		return err
	}
	if err := q.InsertGrantLineageSelf(ctx, org, g.ID.UUID()); err != nil {
		return err
	}
	_, err := audit.Record(ctx, tx, ev)
	return err
}

// RevokeInTx implements app.TxStore: the containment epoch first, then the
// grant and every descendant (HR-047).
func (s *Store) RevokeInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID, ev audit.Event) ([]domain.GrantID, error) {
	return revokeTx(ctx, tx, org, id, ev)
}

func revokeTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id domain.GrantID, ev audit.Event) ([]domain.GrantID, error) {
	q := dbq.New(tx)
	if err := db.ExpectOneRow(q.RaiseContainmentEpoch(ctx, org)); err != nil {
		return nil, fmt.Errorf("grants: containment epoch: %w", err)
	}
	if _, err := q.GetGrant(ctx, org, id.UUID()); db.IsNoRows(err) {
		return nil, app.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	reason := ev.Details["reason"]
	if reason == "" {
		reason = "revoked"
	}
	revoked, err := q.RevokeGrantTree(ctx, &reason, org, id.UUID())
	if err != nil {
		return nil, err
	}
	out := make([]domain.GrantID, 0, len(revoked))
	for _, r := range revoked {
		g, err := domain.ParseGrantID(r.String())
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if ev.Details != nil {
		ev.Details["revoked"] = strconv.Itoa(len(out))
	}
	_, err = audit.Record(ctx, tx, ev)
	return out, err
}

// AutomationGrantsInTx implements app.TxStore.
func (s *Store) AutomationGrantsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, scope string, execution, ceiling ids.UUID,
	agents []ids.UUID,
) ([]ids.UUID, error) {
	q := dbq.New(tx)
	switch scope {
	case app.RevokeScopeExecution:
		return q.ActiveGrantsOfExecution(ctx, org, &execution)
	case app.RevokeScopeCeiling:
		return q.ActiveGrantsOfCeiling(ctx, org, &ceiling)
	case app.RevokeScopeCeilingAgents:
		return q.ActiveRootGrantsOfAgents(ctx, org, agents)
	}
	return nil, fmt.Errorf("grants: unknown revocation scope %q", scope)
}
