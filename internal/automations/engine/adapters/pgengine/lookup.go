// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Execution implements triggers.ExecutionLookup (D59, D75): what a retry
// needs to know about an execution. An execution of another org is not
// found.
func (e *Engine) Execution(ctx context.Context, tx pgx.Tx, org ids.OrgID, id ids.UUID) (triggers.ExecutionInfo, error) {
	r, err := dbq.New(tx).AutomationExecutionInfo(ctx, org, id)
	if db.IsNoRows(err) {
		return triggers.ExecutionInfo{}, ErrNotFound
	} else if err != nil {
		return triggers.ExecutionInfo{}, err
	}
	return triggers.ExecutionInfo{
		Automation: r.AutomationID, Version: r.VersionID, State: autodomain.ExecutionState(r.State),
		UnknownIrreversible: r.UnknownIrreversible, Trigger: r.TriggerID,
	}, nil
}

var _ triggers.ExecutionLookup = (*Engine)(nil)
