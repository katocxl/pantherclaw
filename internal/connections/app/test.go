// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Connection tests (G0 M8 track C, F354, F350): a harmless test of what a
// connection depends on. It never calls the target, so it changes nothing
// there; every result is kept, and the latest passed one is the
// connection's last successful test.

// Test results.
const (
	TestPassed = "PASSED"
	TestFailed = "FAILED"
)

// Check codes, in the order a test makes them.
const (
	CheckConnectionActive   = "CONNECTION_ACTIVE"
	CheckGatewayActive      = "GATEWAY_ACTIVE"
	CheckGatewayCertificate = "GATEWAY_CERTIFICATE"
	CheckPackageRoutes      = "PACKAGE_ROUTES"
	CheckCredential         = "CREDENTIAL"
	CheckCircuitClosed      = "CIRCUIT_CLOSED"
)

// Check is one check of a test.
type Check struct {
	Check  string `json:"check"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// TestResult is one test of a connection.
type TestResult struct {
	ID, Connection ids.UUID
	Result         string
	Checks         []Check
	TestedBy       string
	TestedAt       time.Time
}

func testOf(r dbq.PcConnectionTest) (TestResult, error) {
	out := TestResult{ID: r.ID, Connection: r.ConnectionID, Result: r.Result, TestedBy: r.TestedBy, TestedAt: r.TestedAt}
	return out, json.Unmarshal(r.Checks, &out.Checks)
}

// Test tests a connection and records the result (connection.manage).
func (s *Service) Test(ctx context.Context, id ids.UUID) (TestResult, error) {
	c, err := s.caller(ctx, td.PermConnectionManage)
	if err != nil {
		return TestResult{}, err
	}
	var out TestResult
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		facts, err := q.ConnectionTestFacts(ctx, c.Org, id)
		if err != nil {
			return err
		}
		checks, err := check(ctx, q, conn, facts)
		if err != nil {
			return err
		}
		result := TestPassed
		for _, ch := range checks {
			if !ch.Passed {
				result = TestFailed
			}
		}
		raw, err := json.Marshal(checks, json.Deterministic(true))
		if err != nil {
			return err
		}
		row, err := q.InsertConnectionTest(ctx, dbq.InsertConnectionTestParams{
			OrgID: c.Org, ID: ids.NewV7(), ConnectionID: id, Result: result, Checks: raw, TestedBy: c.By,
		})
		if err != nil {
			return err
		}
		if out, err = testOf(row); err != nil {
			return err
		}
		return record(ctx, tx, c, "connection.tested", id, map[string]string{"result": result, "test_id": row.ID.String()})
	})
	return out, err
}

// check makes a test's checks.
func check(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection, f dbq.ConnectionTestFactsRow) ([]Check, error) {
	out := []Check{
		{CheckConnectionActive, conn.State == StateActive, "The connection is " + conn.State + "."},
		{CheckGatewayActive, f.GatewayState == "ACTIVE", "Its gateway is " + f.GatewayState + "."},
		{CheckGatewayCertificate, f.CertificateCurrent, "The gateway holds a current certificate (it renews every 24 hours)."},
	}
	if !f.CertificateCurrent {
		out[2].Detail = "The gateway holds no current certificate: it has not renewed within 24 hours, or it never enrolled."
	}
	routes, err := routes(ctx, q, conn.OrgID, conn.Package, conn.Kind)
	switch {
	case errors.Is(err, ErrPackage):
		out = append(out, Check{CheckPackageRoutes, false, "The org has no usable pinned version of " + conn.Package + "."})
	case errors.Is(err, ErrNoRoutes):
		out = append(out, Check{CheckPackageRoutes, false, conn.Package + " has no routes a " + conn.Kind + " connection can serve."})
	case err != nil:
		return nil, err
	default:
		out = append(out, Check{CheckPackageRoutes, true, conn.Package + " is pinned and serves " + strconv.Itoa(len(routes)) + " routes."})
	}
	switch {
	case conn.AccessMode != AccessHeld:
		out = append(out, Check{CheckCredential, true, "No credential of PantherClaw's is needed (" + conn.AccessMode + ")."})
	case f.CredentialCurrent:
		out = append(out, Check{CheckCredential, true, "An active credential is sealed to the gateway's active broker key."})
	default:
		out = append(out, Check{CheckCredential, false, "No active credential is sealed to the gateway's active broker key: seal one with pclaw seal."})
	}
	open := Check{CheckCircuitClosed, f.OpenCircuits == 0, "No circuit is open."}
	if !open.Passed {
		open.Detail = strconv.Itoa(int(f.OpenCircuits)) + " circuit(s) are open after repeated UNKNOWN outcomes (HR-078)."
	}
	return append(out, open), nil
}

// lastTest is a connection's latest test, or its latest passed one; ok is
// false when there is none.
func lastTest(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, passedOnly bool) (TestResult, bool, error) {
	r, err := q.LatestConnectionTest(ctx, org, id, passedOnly)
	if db.IsNoRows(err) {
		return TestResult{}, false, nil
	} else if err != nil {
		return TestResult{}, false, err
	}
	t, err := testOf(r)
	return t, err == nil, err
}
