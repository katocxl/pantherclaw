// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// SnapshotMode reports the isolation level and read-only setting of the
// transaction Snapshot runs its evaluation in (HR-504), and the error a
// write in it gets.
func SnapshotMode(ctx context.Context, r *Reader, org ids.OrgID) (isolation, readOnly string, write error, err error) {
	err = r.Snapshot(ctx, org, func(ctx context.Context, pr pipeline.Reader) error {
		tx := pr.(*snapshot).tx
		if err := tx.QueryRow(ctx, "SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')").
			Scan(&isolation, &readOnly); err != nil {
			return err
		}
		_, write = tx.Exec(ctx, "UPDATE pc.budget_accounts SET reserved = reserved")
		return nil
	})
	return isolation, readOnly, write, err
}
