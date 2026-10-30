// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// Downstream state (G0 M17 D102, F414). A confirmed action whose decision
// predicted consequences carries their state apart from its own effect:
// set when its consequences are opened, then rolled up from the
// consequence transactions each time one of them changes, in the same
// database transaction. Only the consequences' own evidence makes it
// CONFIRMED, which appends an effect receipt at level downstream (basis
// consequence); earlier receipts are never rewritten (HR-451).

// downstreamAfterOpen is an action's downstream state once its predicted
// consequences were processed: NOT_VERIFIABLE when any could not be opened
// for verification (it never becomes CONFIRMED, HR-450), PENDING when
// transactions were opened.
func downstreamAfterOpen(opened, skipped int) domain.DownstreamState {
	switch {
	case skipped > 0:
		return domain.DownstreamNotVerifiable
	case opened > 0:
		return domain.DownstreamPending
	default:
		return ""
	}
}

// setDownstream records txn's downstream state; empty clears it. A
// NOT_VERIFIABLE state also sets the cap that no later roll-up lifts
// (D131).
func setDownstream(ctx context.Context, q *dbq.Queries, org ids.OrgID, txn ids.UUID, s domain.DownstreamState) error {
	var state *string
	if s != "" {
		v := string(s)
		state = &v
	}
	return q.SetDownstreamState(ctx, dbq.SetDownstreamStateParams{
		State: state, NotVerifiable: s == domain.DownstreamNotVerifiable, OrgID: org, ID: txn,
	})
}

// rollUp computes again the downstream state of the action consequence was
// opened for, after consequence's effect or reconciliation changed, and of
// that action's own parent in turn when it is itself a consequence. A
// transaction that is no consequence changes nothing.
func rollUp(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, consequence ids.UUID, sign app.Sign,
	actor evdomain.Actor, now time.Time,
) error {
	parent, err := q.ConsequenceParent(ctx, org, consequence)
	if db.IsNoRows(err) {
		return nil
	} else if err != nil {
		return err
	}
	cur, err := q.TransactionDownstream(ctx, org, parent)
	if err != nil {
		return err
	}
	was := domain.DownstreamState(deref(cur.DownstreamState, ""))
	// Nothing was processed for it yet. A NOT_VERIFIABLE action still
	// rolls up: a negative outcome makes it UNCONFIRMED (D131).
	if was == "" {
		return nil
	}
	rows, err := q.ConsequenceStates(ctx, org, parent)
	if err != nil {
		return err
	}
	cs := make([]domain.Consequence, len(rows))
	txns := make([]ids.UUID, len(rows))
	for i, r := range rows {
		cs[i] = domain.Consequence{
			Effect: domain.EffectState(deref(r.EffectState, "")), Downstream: domain.DownstreamState(deref(r.DownstreamState, "")),
			Questioned: r.Questioned,
		}
		txns[i] = r.ID
	}
	next := domain.Downstream(cs, cur.DownstreamNotVerifiable)
	if next == was {
		return nil
	}
	if err := setDownstream(ctx, q, org, parent, next); err != nil {
		return err
	}
	// The action's receipt at level downstream, while its own effect is
	// still confirmed (a compensated action keeps its state).
	if next == domain.DownstreamConfirmed && domain.EffectState(deref(cur.EffectState, "")) == domain.Confirmed {
		e := app.Effect{
			Org: org, Transaction: parent, State: domain.Confirmed, Basis: app.BasisConsequence,
			Required: defs.Level(deref(cur.EffectLevelRequired, string(defs.LevelAcceptance))), Achieved: defs.LevelDownstream,
			Consequences: txns, Reason: "CONSEQUENCES_CONFIRMED", At: now,
		}
		if err := appendEffect(ctx, tx, q, e, actor, sign); err != nil {
			return err
		}
	}
	return rollUp(ctx, tx, q, org, parent, sign, actor, now)
}
