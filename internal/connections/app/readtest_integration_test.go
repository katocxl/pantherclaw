// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// readTest asks for a read test and returns it with the lease the
// connection's gateway then claims.
func (e *env) readTest(t *testing.T, s *txapp.Service, conn ids.UUID) (app.TestResult, txapp.Lease) {
	t.Helper()
	r, err := e.svc.Test(e.admin, conn, app.KindReadTest)
	if err != nil || r.Kind != app.KindReadTest || r.Operation != "payments.account.read" || r.State != "PENDING" || r.Result != "" || r.FinishedAt != nil {
		t.Fatalf("read test %+v %v", r, err)
	}
	leases, err := s.Claim(context.Background(), e.org, e.gateway, 16)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	return r, leases[0]
}

// testRow is a test's stored state, result and checks.
func (e *env) testRow(t *testing.T, id ids.UUID) (state, result string, checks []app.Check, gateway bool) {
	t.Helper()
	var raw []byte
	var res *string
	var gw *ids.UUID
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT state, result, checks, gateway_id FROM pc.connection_tests WHERE id = $1", id).Scan(&state, &res, &raw, &gw)
	}); err != nil {
		t.Fatal(err)
	}
	if res != nil {
		result = *res
	}
	if err := json.Unmarshal(raw, &checks); err != nil {
		t.Fatal(err)
	}
	return state, result, checks, gw != nil && *gw == e.gateway
}

// TestF354_ReadTestsAreLeasedToTheConnectionsGateway: a read test leases
// the package's one test read (a GET with no params, against the
// connection itself) to the connection's gateway as a connection_test task
// with no transaction. It is RUNNING once leased. A 2xx passes it and
// becomes the last successful test; another status fails it, naming the
// status; a read the gateway could not make is retried and, after three
// attempts, the test could not run, as when its task expires. A report
// with fields is refused. Read tests run only on an ACTIVE http connection
// whose gateway holds its credential or needs none, and need
// connection.test, which only the Gateway Admin holds.
func TestF354_ReadTestsAreLeasedToTheConnectionsGateway(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.epoch(t) // containment state, which leasing reads
	c := e.payments(t, "payments")
	s := &txapp.Service{Store: &pgtransactions.Store{Pool: e.pool}}

	r, l := e.readTest(t, s, c.ID)
	var req app.TestReadRequest
	if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil || l.Purpose != txdomain.PurposeConnectionTest ||
		l.Operation != "payments.account.read" || l.Correlate != "" || req.Mode != app.TestReadMode || req.Target.Type != "pc.connection" ||
		req.Target.ID != c.ID.String() || len(req.Params) != 0 {
		t.Fatalf("lease %+v, request %s", l, l.Request)
	}
	if st, _, _, gw := e.testRow(t, r.ID); st != "RUNNING" || !gw {
		t.Fatalf("a leased test is %s (gateway %v)", st, gw)
	}
	if _, err := s.Report(ctx, e.org, e.gateway, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200,
		Fields: map[string]string{"/id": "acct_1"},
	}); !errors.Is(err, txapp.ErrUndeclared) {
		t.Fatalf("a report with fields: %v", err)
	}
	digest := bytes.Repeat([]byte{7}, 32)
	if a, err := s.Report(ctx, e.org, e.gateway, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, ResponseDigest: digest}); err != nil || !a.Done {
		t.Fatalf("report: %+v %v", a, err)
	}
	st, res, checks, gw := e.testRow(t, r.ID)
	if st != "DONE" || res != app.TestPassed || !gw || len(checks) != 1 || checks[0].Check != app.CheckTestRead || !checks[0].Passed {
		t.Fatalf("passed test %s %s %+v", st, res, checks)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.connection_tests WHERE id = $1 AND detail_sha256 = $2`, r.ID, digest); n != 1 {
		t.Fatal("the report's digest was not kept")
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.verifications WHERE connection_id = $1 AND purpose = 'connection_test'
		AND transaction_id IS NULL AND state = 'DONE'`, c.ID); n != 1 {
		t.Fatal("the task did not end DONE")
	}
	if caps, err := e.svc.Capabilities(e.admin, c.ID); err != nil || caps.LastPassedTest == nil || caps.LastPassedTest.ID != r.ID {
		t.Fatalf("last passed test %+v %v", caps.LastPassedTest, err)
	}
	if _, err := s.Report(ctx, e.org, e.gateway, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 500}); !errors.Is(err, txapp.ErrLease) {
		t.Fatalf("a second report: %v", err)
	}

	refused, l := e.readTest(t, s, c.ID)
	if _, err := s.Report(ctx, e.org, e.gateway, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 401}); err != nil {
		t.Fatal(err)
	}
	if st, res, checks, _ := e.testRow(t, refused.ID); st != "DONE" || res != app.TestFailed || checks[0].Passed ||
		checks[0].Detail != "The target answered HTTP 401 to payments.account.read." {
		t.Fatalf("refused test %s %s %+v", st, res, checks)
	}

	unreachable, l := e.readTest(t, s, c.ID)
	for attempt := 1; ; attempt++ {
		a, err := s.Report(ctx, e.org, e.gateway, txapp.Report{Task: l.Task, Secret: l.Secret})
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 3 {
			if !a.Done {
				t.Fatal("a third failed read did not end the test")
			}
			break
		}
		e.exec(t, "UPDATE pc.verifications SET next_at = now() WHERE id = $1", l.Task)
		leases, err := s.Claim(ctx, e.org, e.gateway, 16)
		if a.Done || err != nil || len(leases) != 1 {
			t.Fatalf("attempt %d: %+v %+v %v", attempt, a, leases, err)
		}
		l = leases[0]
	}
	if st, res, checks, _ := e.testRow(t, unreachable.ID); st != "FAILED" || res != "" || checks[0].Passed {
		t.Fatalf("unreachable test %s %s %+v", st, res, checks)
	}

	expired, err := e.svc.Test(e.admin, c.ID, app.KindReadTest)
	if err != nil {
		t.Fatal(err)
	}
	e.dbt.AdminExec(t, "UPDATE pc.verifications SET deadline_at = created_at + interval '1 millisecond' WHERE org_id = $1 AND purpose = 'connection_test' AND state = 'PENDING'", e.org)
	if _, err := s.Expire(ctx, e.org); err != nil {
		t.Fatal(err)
	}
	if st, _, checks, _ := e.testRow(t, expired.ID); st != "FAILED" || len(checks) != 1 || checks[0].Passed {
		t.Fatalf("expired test %s %+v", st, checks)
	}

	agentHeld, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "held-by-agent", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test/v1/", Gateway: e.gateway,
		AccessMode: app.AccessAgentHeld,
	})
	if err != nil {
		t.Fatal(err)
	}
	shell, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "laptop", Kind: app.KindLocal, Package: "pc.shell", Gateway: e.gateway, AccessMode: app.AccessNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]ids.UUID{"agent held": agentHeld.ID, "local": shell.ID} {
		if _, err := e.svc.Test(e.admin, id, app.KindReadTest); !errors.Is(err, app.ErrReadTest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.Test(e.admin, c.ID, "write"); !errors.Is(err, app.ErrShape) {
		t.Errorf("another kind: %v", err)
	}
	if _, err := e.svc.Test(e.caller(td.KindUser, td.RoleDeveloper), c.ID, app.KindReadTest); !denied(err) {
		t.Errorf("a developer: %v", err)
	}
}
