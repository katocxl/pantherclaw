// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Rollout implements steps.Rollout from the automation's row (D55).
type Rollout struct{}

// Cohort returns the automation's rollout and, for COHORT, its agents.
func (Rollout) Cohort(ctx context.Context, tx pgx.Tx, org ids.OrgID, automation ids.UUID) (autodomain.Rollout, []ids.UUID, error) {
	r, err := dbq.New(tx).AutomationRolloutOf(ctx, org, automation)
	if err != nil {
		return "", nil, err
	}
	if r.Rollout == nil {
		return "", nil, nil
	}
	return autodomain.Rollout(*r.Rollout), r.CohortAgents, nil
}

// Recipients implements steps.Recipients (D25 notify): OWNER the
// automation's owner, CONFIRMERS the people who approved its authority,
// APPROVERS the people who approved this execution's gates, TRIGGER_OWNER
// the owner of the agent the trigger is about.
type Recipients struct{}

// Resolve returns the people of one scope.
func (Recipients) Resolve(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, scope string) ([]ids.UUID, error) {
	ex := sc.Execution
	switch scope {
	case autodomain.ScopeOwner:
		return []ids.UUID{ex.Owner}, nil
	case autodomain.ScopeConfirmers:
		return ex.Confirmers, nil
	case autodomain.ScopeApprovers:
		return dbq.New(tx).ExecutionGateApprovers(ctx, sc.Org, &ex.ID)
	case autodomain.ScopeTriggerOwner:
		for _, s := range ex.Trigger.Subjects {
			if s.Type != reflexdomain.SubjectAgent {
				continue
			}
			agent, err := ids.ParseUUID(s.ID)
			if err != nil {
				continue
			}
			owner, err := dbq.New(tx).AgentOwnerOf(ctx, sc.Org, agent)
			if db.IsNoRows(err) || err == nil && owner == nil {
				return nil, nil
			} else if err != nil {
				return nil, err
			}
			return []ids.UUID{*owner}, nil
		}
	}
	return nil, nil
}

// Reconciliation implements Reconciler (D27): an execution in
// NEEDS_RECONCILIATION is resolved once none of its runs' allowed
// transactions is left without a known outcome (M7 reconciliation); it
// changed something when any is confirmed.
type Reconciliation struct{}

// Reconciled reports whether the execution's outcomes are all known.
func (Reconciliation) Reconciled(ctx context.Context, tx pgx.Tx, x *engine.Exec) (bool, bool, error) {
	r, err := dbq.New(tx).ExecutionUnresolved(ctx, x.Org, &x.ID)
	if err != nil {
		return false, false, err
	}
	return r.Unresolved == 0, r.Changed > 0, nil
}
