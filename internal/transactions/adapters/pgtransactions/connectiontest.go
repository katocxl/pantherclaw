// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
)

// A connection test's read (G0 M8 track C, F354): the connection's
// gateway runs the package's test read under a connection_test lease and
// reports what the target answered. A 2xx passes the test and any other
// answer fails it, with the status. A read the gateway could not make is
// tried again, and after maxTestAttempts the test could not run. Nothing
// here touches a transaction, and a test read declares no fields.

// maxTestAttempts is how often a test read is tried before the test is
// FAILED (could not run).
const maxTestAttempts = 3

// testCheck is a test's check as the connections service stores it.
type testCheck struct {
	Check  string `json:"check"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// connectionTest applies a report under a connection_test lease.
func (s *Store) connectionTest(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID,
	task dbq.LeasedConnectionTestRow, r app.Report,
) (app.Applied, error) {
	if len(r.Fields) > 0 || len(r.Items) > 0 {
		return app.Applied{}, app.ErrUndeclared
	}
	id, attempt := task.ID, task.Attempts
	o := dbq.InsertObservationParams{
		OrgID: org, ID: ids.NewV7(), Source: "verifier", VerificationID: &id, GatewayID: gateway, Attempt: &attempt,
	}
	answered := r.HTTPStatus >= 100 && r.HTTPStatus <= 599
	if answered {
		st := int32(r.HTTPStatus) //nolint:gosec // G115: 100..599
		o.HttpStatus = &st
	}
	if len(r.ResponseDigest) == sha256.Size {
		o.ResponseDigest = r.ResponseDigest
	}
	if err := q.InsertObservation(ctx, o); err != nil {
		return app.Applied{}, err
	}
	out := app.Applied{Observation: o.ID, Done: true}
	if !answered {
		if task.Attempts < maxTestAttempts {
			out.Done = false
			return out, q.RetryVerification(ctx, app.Backoff(int(task.Attempts)).Seconds(), org, task.ID)
		}
		if err := q.FinishVerification(ctx, "EXPIRED", org, task.ID); err != nil {
			return app.Applied{}, err
		}
		return out, finishTest(ctx, tx, q, org, gateway, task, "FAILED", "", testCheck{
			Check: "TEST_READ", Detail: fmt.Sprintf("The gateway could not make the test read in %d attempts.", task.Attempts),
		}, nil)
	}
	result, passed := "FAILED", r.HTTPStatus >= 200 && r.HTTPStatus <= 299
	if passed {
		result = "PASSED"
	}
	if err := q.FinishVerification(ctx, "DONE", org, task.ID); err != nil {
		return app.Applied{}, err
	}
	return out, finishTest(ctx, tx, q, org, gateway, task, "DONE", result, testCheck{
		Check: "TEST_READ", Passed: passed, Detail: fmt.Sprintf("The target answered HTTP %d to %s.", r.HTTPStatus, task.Operation),
	}, o.ResponseDigest)
}

// finishTest records a test's end and audits it as the gateway.
func finishTest(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, task dbq.LeasedConnectionTestRow,
	state, result string, c testCheck, digest []byte,
) error {
	checks, err := json.Marshal([]testCheck{c}, json.Deterministic(true))
	if err != nil {
		return err
	}
	p := dbq.FinishConnectionTestParams{
		State: state, Checks: checks, GatewayID: &gateway, DetailSha256: digest, OrgID: org, ID: task.TestID,
	}
	if result != "" {
		p.Result = &result
	}
	if err := q.FinishConnectionTest(ctx, p); err != nil {
		return err
	}
	details := map[string]string{"kind": "read", "test_id": task.TestID.String(), "state": state}
	if result != "" {
		details["result"] = result
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "connection.tested", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "connection", ID: task.ConnectionID.String()}, Details: details,
	})
	return err
}
