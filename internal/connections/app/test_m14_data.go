// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// PostgresTestOperation is what a postgres connection's read test names:
// the gateway runs the role check (G0 M14 D18, HR-309) instead of a read,
// and answers 200 when the role passes and 403 when it does not.
const PostgresTestOperation = "postgres.tables.read"

// postgresTest leases a postgres connection's read test to its gateway: the
// HR-309 role check through the connection's sealed credential. Only a
// read test applies; a target_verifier test needs an http connection.
func postgresTest(ctx context.Context, q *dbq.Queries, c actor, conn dbq.PcConnection, kind string) (dbq.PcConnectionTest, error) {
	switch {
	case kind == KindVerifierTest:
		return dbq.PcConnectionTest{}, ErrVerifierTest
	case conn.State != StateActive:
		return dbq.PcConnectionTest{}, ErrReadTest
	}
	request, err := json.Marshal(TestReadRequest{
		Mode: TestReadMode, Target: actionir.Target{Type: domain.ConnectionTarget, ID: conn.ID.String()}, Params: map[string]string{},
	}, json.Deterministic(true))
	if err != nil {
		return dbq.PcConnectionTest{}, err
	}
	task, op := ids.NewV7(), PostgresTestOperation
	if err := q.InsertConnectionTestTask(ctx, dbq.InsertConnectionTestTaskParams{
		OrgID: c.Org, ID: task, ConnectionID: conn.ID, Operation: op, Request: request,
	}); err != nil {
		return dbq.PcConnectionTest{}, err
	}
	return q.InsertLeasedConnectionTest(ctx, dbq.InsertLeasedConnectionTestParams{
		OrgID: c.Org, ID: ids.NewV7(), ConnectionID: conn.ID, Kind: kind, VerificationID: &task, Operation: &op, RequestedBy: c.By,
	})
}
