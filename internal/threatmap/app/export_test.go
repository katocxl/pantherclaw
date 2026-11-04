// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// SnapshotDispatcherForTest is the dispatcher RegisterSnapshots registers,
// for a test that runs it once (G0 M28 D727a).
func SnapshotDispatcherForTest(pool *db.Pool) river.Worker[SnapshotDispatchArgs] {
	return &snapshotDispatcher{pool: pool}
}
