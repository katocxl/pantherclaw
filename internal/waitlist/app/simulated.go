// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// SimulatedTransactions returns which of the transactions belong to a range
// run (HR-222); a console shows a SIMULATED banner on their entries.
func (r *Reader) SimulatedTransactions(ctx context.Context, txns []ids.UUID) (map[ids.UUID]bool, error) {
	out := map[ids.UUID]bool{}
	if len(txns) == 0 {
		return out, nil
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	err = r.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).SimulatedTransactions(ctx, c.Org, txns)
		for _, id := range rows {
			out[id] = true
		}
		return err
	}, db.ReadOnly())
	return out, err
}
