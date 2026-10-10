// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// writeInputs stores an evaluation's sealed inputs next to its receipt, in
// the receipt's transaction (G0 M7 design decision 11). The Authority
// sealed them before the transaction began.
func writeInputs(ctx context.Context, tx db.TenantTx, org ids.OrgID, txn ids.UUID, evaluation int, in *recording.Sealed) error {
	if in == nil {
		return nil
	}
	return dbq.New(tx).InsertEvaluationInputs(ctx, dbq.InsertEvaluationInputsParams{
		OrgID: org, TransactionID: txn, Evaluation: int32(evaluation), //nolint:gosec // ≤ 33
		FormatVersion: int32(in.Format), PipelineVersion: int32(in.Pipeline), //nolint:gosec // small versions
		Inputs: in.Inputs, InputsSha256: in.Digest[:], Truncated: in.Truncated,
	})
}
