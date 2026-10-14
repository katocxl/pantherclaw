// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ConnectionTests is the TargetVerifier over M8's connection tests
// (pc.connection_tests, HR-210): it only reads them, in the caller's tenant
// transaction. Of an operation's target_verifier tests on a connection only
// the latest finished one counts, and only while it is DONE and PASSED: a
// newer failure, or a test that could not run, drops the lift. A test that
// finished before the connection's latest revision, its active credential
// or its package pin vouches for nothing (HR-211). A test vouches only for
// the operation it ran (founder decision N15); whether the operation may be
// lifted at all is coverage's own decision (a read, in M9).
type ConnectionTests struct{}

// LastPassed implements TargetVerifier.
func (ConnectionTests) LastPassed(ctx context.Context, tx db.TenantTx, connection ids.UUID, operation string) (*time.Time, error) {
	row, err := dbq.New(tx).LatestTargetVerifierTest(ctx, tx.OrgID(), connection, &operation)
	switch {
	case db.IsNoRows(err):
		return nil, nil
	case err != nil:
		return nil, err
	case row.State != "DONE" || row.Result == nil || *row.Result != "PASSED" || row.FinishedAt == nil:
		return nil, nil
	}
	at := *row.FinishedAt
	return &at, nil
}
