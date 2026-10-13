// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// writeConsequences stores what an evaluation's consequence rules said,
// next to its receipt and in the receipt's transaction (G0 M8, HR-206). A
// rule that could not be evaluated is no consequence: the receipt's
// checklist says why the evaluation could not authorize.
func writeConsequences(ctx context.Context, tx db.TenantTx, org ids.OrgID, txn ids.UUID, evaluation int, cs []consequences.Consequence) error {
	q := dbq.New(tx)
	for i, c := range cs {
		if c.Err != nil {
			continue
		}
		unknown, err := json.Marshal(c.Unknown)
		if err != nil {
			return err
		}
		if c.Unknown == nil {
			unknown = []byte("[]")
		}
		envs := c.Environments
		if envs == nil {
			envs = []string{}
		}
		if err := q.InsertDecisionConsequence(ctx, dbq.InsertDecisionConsequenceParams{
			OrgID: org, TransactionID: txn, Evaluation: int32(evaluation), Position: int32(i), //nolint:gosec // ≤ 33 and ≤ 255
			RuleID: c.Rule, Operation: c.Operation, TargetType: c.Target.Type, TargetID: c.Target.ID, Environments: envs,
			State: string(c.State), Unknown: unknown, FactsDigest: c.FactsDigest,
		}); err != nil {
			return err
		}
	}
	return nil
}
