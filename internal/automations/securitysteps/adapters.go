// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securitysteps

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store adapters over the platform's tables, read in the driver's
// transaction. Server wiring uses them; tests use fakes.

// Actions reads response actions (ActionStatus).
type Actions struct{}

var _ ActionStatus = Actions{}

// Status implements ActionStatus.
func (Actions) Status(ctx context.Context, tx pgx.Tx, org ids.OrgID, action ids.UUID) (string, error) {
	a, err := dbq.New(tx).GetResponseAction(ctx, org, action)
	if err != nil {
		return "", err
	}
	return a.Status, nil
}

// StoreOwners resolves agent and connection owners (Owners).
type StoreOwners struct{}

var _ Owners = StoreOwners{}

// AgentOwner implements Owners.
func (StoreOwners) AgentOwner(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent ids.UUID) (*ids.UUID, error) {
	a, err := dbq.New(tx).GetAgent(ctx, org, agent)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return a.OwnerUserID, nil
}

// ConnectionOwner implements Owners: connections record who created them
// ("user:<id>"); one a service created has no owner.
func (StoreOwners) ConnectionOwner(ctx context.Context, tx pgx.Tx, org ids.OrgID, connection ids.UUID) (*ids.UUID, error) {
	by, err := dbq.New(tx).AutomationOwnerOfConnection(ctx, org, connection)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	id, ok := strings.CutPrefix(by, "user:")
	if !ok {
		return nil, nil
	}
	u, ok := parseID(id)
	if !ok {
		return nil, nil
	}
	return &u, nil
}

// Nudger sends reminders and escalations for an approval request's open
// waitlist entry (waitlist/app.Router.NudgeForAutomationTx).
type Nudger interface {
	NudgeForAutomationTx(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, escalate bool, dedupe string) (int, error)
}

// StoreApprovals implements Approvals over the approval requests and the
// waitlist router.
type StoreApprovals struct {
	Nudger Nudger
}

var _ Approvals = StoreApprovals{}

// RequestOf implements Approvals.
func (StoreApprovals) RequestOf(ctx context.Context, tx pgx.Tx, org ids.OrgID, transaction ids.UUID) (ids.UUID, bool, error) {
	r, err := dbq.New(tx).LatestApprovalRequestOfTransaction(ctx, org, &transaction)
	if db.IsNoRows(err) {
		return ids.UUID{}, false, nil
	} else if err != nil {
		return ids.UUID{}, false, err
	}
	return r.ID, true, nil
}

// Nudge implements Approvals.
func (a StoreApprovals) Nudge(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID, escalate bool, dedupe string) (int, error) {
	if a.Nudger == nil {
		return 0, ErrUnwired
	}
	return a.Nudger.NudgeForAutomationTx(ctx, tx, org, request, escalate, dedupe)
}

// Resolution implements Approvals. A request is resolved once no one can
// decide it any more and an approval was used or lapsed: APPROVED waits
// for the held action to run (CONSUMED) or the approval to expire.
func (StoreApprovals) Resolution(ctx context.Context, tx pgx.Tx, org ids.OrgID, request ids.UUID) (Resolution, error) {
	q := dbq.New(tx)
	r, err := q.GetApprovalRequest(ctx, org, request)
	if err != nil {
		return Resolution{}, err
	}
	res := Resolution{State: r.State, Transaction: r.TransactionID}
	switch r.State {
	case "PENDING", "EVIDENCE_REQUESTED", "APPROVED":
	default:
		res.Resolved = true
	}
	if res.Resolved && r.TransactionID != nil {
		t, err := q.AutomationTransactionOutcome(ctx, org, *r.TransactionID)
		switch {
		case db.IsNoRows(err):
		case err != nil:
			return Resolution{}, err
		default:
			res.Outcome = t.State
			if t.EffectState != nil {
				res.Outcome += "/" + *t.EffectState
			}
		}
	}
	return res, nil
}
