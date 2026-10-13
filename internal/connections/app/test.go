// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
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
	// Kind is credential, read or target_verifier; State PENDING, RUNNING,
	// DONE or FAILED (could not run); Result PASSED or FAILED once DONE.
	Kind, State, Result string
	// Operation is the operation a read or target_verifier test reached.
	Operation   string
	Checks      []Check
	RequestedBy string
	CreatedAt   time.Time
	FinishedAt  *time.Time
}

func testOf(r dbq.PcConnectionTest) (TestResult, error) {
	out := TestResult{
		ID: r.ID, Connection: r.ConnectionID, Kind: r.Kind, State: r.State, RequestedBy: r.RequestedBy, CreatedAt: r.CreatedAt,
		FinishedAt: r.FinishedAt,
	}
	if r.Operation != nil {
		out.Operation = *r.Operation
	}
	if r.Result != nil {
		out.Result = *r.Result
	}
	return out, json.Unmarshal(r.Checks, &out.Checks)
}

// Test kinds.
const (
	// KindCredentialTest checks what the connection depends on, at once,
	// without calling the target.
	KindCredentialTest = "credential"
	// KindReadTest leases the package's harmless test read to the
	// connection's gateway.
	KindReadTest = "read"
	// KindVerifierTest leases the same read to the gateway of a
	// target_enforced connection, which sends it four times to show the
	// target's verifier refuses it without a valid action token (N15).
	KindVerifierTest = "target_verifier"
)

// CheckTestRead is a read test's one check: what the target answered.
const CheckTestRead = "TEST_READ"

var (
	// ErrNoTestRead: the connection's package declares no test read.
	ErrNoTestRead = pcerr.New(pcerr.FailedPrecondition, "NO_TEST_READ", "the connection's package declares no harmless test read")
	// ErrReadTest: the connection is not one a read test can run through.
	ErrReadTest = pcerr.New(pcerr.FailedPrecondition, "READ_TEST_NOT_POSSIBLE",
		"a read test needs an ACTIVE http connection whose gateway holds its credential or needs none")
	// ErrVerifierTest: the connection is not one a target_verifier test can
	// run through.
	ErrVerifierTest = pcerr.New(pcerr.FailedPrecondition, "VERIFIER_TEST_NOT_POSSIBLE",
		"a target_verifier test needs an ACTIVE http connection in target_enforced access mode")
)

// Test tests a connection and records the test (connection.test): a
// credential test at once, or a read test that the connection's gateway
// runs and reports.
func (s *Service) Test(ctx context.Context, id ids.UUID, kind string) (TestResult, error) {
	c, err := s.caller(ctx, td.PermConnectionTest)
	if err != nil {
		return TestResult{}, err
	}
	if kind == "" {
		kind = KindCredentialTest
	}
	if kind != KindCredentialTest && kind != KindReadTest && kind != KindVerifierTest {
		return TestResult{}, ErrShape
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
		var row dbq.PcConnectionTest
		details := map[string]string{"kind": kind}
		if kind != KindCredentialTest {
			if row, err = leasedTest(ctx, q, c, conn, kind); err != nil {
				return err
			}
		} else {
			if row, err = credentialTest(ctx, q, c, conn); err != nil {
				return err
			}
			details["result"] = *row.Result
		}
		if out, err = testOf(row); err != nil {
			return err
		}
		details["test_id"] = row.ID.String()
		return record(ctx, tx, c, "connection.tested", id, details)
	})
	return out, err
}

// credentialTest checks what the connection depends on and records the
// result.
func credentialTest(ctx context.Context, q *dbq.Queries, c actor, conn dbq.PcConnection) (dbq.PcConnectionTest, error) {
	facts, err := q.ConnectionTestFacts(ctx, c.Org, conn.ID)
	if err != nil {
		return dbq.PcConnectionTest{}, err
	}
	checks, err := check(ctx, q, conn, facts)
	if err != nil {
		return dbq.PcConnectionTest{}, err
	}
	result := TestPassed
	for _, ch := range checks {
		if !ch.Passed {
			result = TestFailed
		}
	}
	raw, err := json.Marshal(checks, json.Deterministic(true))
	if err != nil {
		return dbq.PcConnectionTest{}, err
	}
	return q.InsertCredentialTest(ctx, dbq.InsertCredentialTestParams{
		OrgID: c.Org, ID: ids.NewV7(), ConnectionID: conn.ID, Result: &result, Checks: raw, RequestedBy: c.By,
	})
}

// leasedTest leases the package's test read to the connection's gateway: a
// verification task of purpose connection_test (M7's machinery) that the
// gateway runs through the connection and reports; the test is PENDING
// until then. The package format makes the test read a GET with no
// required params, this checks it again, and the gateway checks it once
// more before it runs it: a test never writes.
// A read test runs it once, through a connection whose gateway holds its
// credential or needs none. A target_verifier test runs it through a
// target_enforced connection, whose gateway asks for test-purpose action
// tokens for this read only.
func leasedTest(ctx context.Context, q *dbq.Queries, c actor, conn dbq.PcConnection, kind string) (dbq.PcConnectionTest, error) {
	mode := TestReadMode
	switch {
	case conn.State != StateActive || conn.Kind != KindHTTP:
		if kind == KindVerifierTest {
			return dbq.PcConnectionTest{}, ErrVerifierTest
		}
		return dbq.PcConnectionTest{}, ErrReadTest
	case kind == KindVerifierTest:
		if conn.AccessMode != AccessTargetEnforced {
			return dbq.PcConnectionTest{}, ErrVerifierTest
		}
		mode = VerifierTestMode
	case conn.AccessMode != AccessHeld && conn.AccessMode != AccessNone:
		return dbq.PcConnectionTest{}, ErrReadTest
	}
	p, err := pinnedPackage(ctx, q, c.Org, conn.Package)
	if err != nil {
		return dbq.PcConnectionTest{}, err
	}
	d, ok := p.TestRead()
	if !ok {
		return dbq.PcConnectionTest{}, ErrNoTestRead
	}
	request, err := json.Marshal(TestReadRequest{
		Mode: mode, Target: actionir.Target{Type: domain.ConnectionTarget, ID: conn.ID.String()}, Params: map[string]string{},
	}, json.Deterministic(true))
	if err != nil {
		return dbq.PcConnectionTest{}, err
	}
	task := ids.NewV7()
	if err := q.InsertConnectionTestTask(ctx, dbq.InsertConnectionTestTaskParams{
		OrgID: c.Org, ID: task, ConnectionID: conn.ID, Operation: d.Operation, Request: request,
	}); err != nil {
		return dbq.PcConnectionTest{}, err
	}
	return q.InsertLeasedConnectionTest(ctx, dbq.InsertLeasedConnectionTestParams{
		OrgID: c.Org, ID: ids.NewV7(), ConnectionID: conn.ID, Kind: kind, VerificationID: &task, Operation: &d.Operation,
		RequestedBy: c.By,
	})
}

// TestReadMode is the mode of a read test's task request.
const TestReadMode = "connection_test"

// VerifierTestMode is a target_verifier test's request mode (N15).
const VerifierTestMode = "target_verifier"

// TestReadRequest is a read test's task request, which the gateway reads:
// the connection itself as the target and no params.
type TestReadRequest struct {
	Mode   string            `json:"mode"`
	Target actionir.Target   `json:"target"`
	Params map[string]string `json:"params"`
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
