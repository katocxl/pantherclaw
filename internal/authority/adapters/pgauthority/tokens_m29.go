// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/modelusage/adapters/pgmodelusage"
	mudomain "github.com/katocxl/pantherclaw/internal/modelusage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// modelUsage writes a model call's usage row in the transaction that
// records its outcome (G0 M29 D825): for every create or count operation
// over a model connection, UNKNOWN outcomes with zeros. The estimate needs
// Team now (D829).
func (s *Store) modelUsage(ctx context.Context, tx db.TenantTx, pc dbq.ExecutionContextRow, txn ids.UUID,
	o finalize.Outcome, u *finalize.ModelUsage, now time.Time,
) error {
	if pc.ConnectionID == nil || pc.ConnectionKind == nil || *pc.ConnectionKind != "model" {
		return nil
	}
	call := pgmodelusage.Call{
		TransactionID: txn, ConnectionID: *pc.ConnectionID,
		Outcome: mudomain.Outcome(strings.ToUpper(string(o))), RecordedAt: now,
	}
	if u != nil {
		call.Usage = mudomain.Usage{
			InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
			CacheReadTokens: u.CacheReadTokens, CacheWriteTokens: u.CacheWriteTokens, Reported: u.Reported,
		}
	}
	if s.TokenCostReports != nil {
		call.Estimates = s.TokenCostReports(ctx, tx.OrgID())
	}
	_, err := pgmodelusage.Store{}.RecordCall(ctx, tx, call)
	return err
}
