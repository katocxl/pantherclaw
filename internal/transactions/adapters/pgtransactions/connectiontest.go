// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
)

// A connection test's read (G0 M8 track C, F354): the connection's
// gateway runs the package's test read under a connection_test lease and
// reports what the target answered. A read test passes on a 2xx and fails
// on any other answer, with the status. A target_verifier test (N15)
// reports its four requests, and passes only when the target's verifier
// refused the three it must refuse with its own problem documents and let
// the fresh one through. A read the gateway could not make is tried again,
// and after maxTestAttempts the test could not run. Nothing here touches a
// transaction.

// maxTestAttempts is how often a test read is tried before the test is
// FAILED (could not run).
const maxTestAttempts = 3

// kindVerifierTest is the connection test kind whose report carries its
// four requests.
const kindVerifierTest = "target_verifier"

// testCheck is a test's check as the connections service stores it.
type testCheck struct {
	Check  string `json:"check"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// verifierRequest is one request of a target_verifier test: the report
// field that carries "<status> <problem type>", and what the target's
// verifier must answer (PAP-1 §10; the problem types are the SDK
// verifiers', urn:pantherclaw:action-token:<code>).
type verifierRequest struct {
	field, check, what string
	status             int // 0: any 2xx
	problem            string
}

var verifierRequests = []verifierRequest{
	{"/missing", "VERIFIER_MISSING", "a request without an action token", 401, "urn:pantherclaw:action-token:missing"},
	{"/body_mismatch", "VERIFIER_BODY_MISMATCH", "a token bound to another body", 401, "urn:pantherclaw:action-token:body_mismatch"},
	{"/fresh", "VERIFIER_FRESH", "a fresh token", 0, ""},
	{"/replayed", "VERIFIER_REPLAYED", "the same token again", 409, "urn:pantherclaw:action-token:replayed"},
}

// MintTestTokens implements app.Store: HR-188's exception, checked again
// here whatever the gateway checked.
func (s *Store) MintTestTokens(ctx context.Context, org ids.OrgID, gateway, task ids.UUID, secret []byte,
	mint func(app.VerifierTest) (app.MintedTokens, error),
) (app.TestTokens, error) {
	var out app.TestTokens
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		hash := sha256.Sum256(secret)
		ct, err := q.LeasedConnectionTest(ctx, dbq.LeasedConnectionTestParams{OrgID: org, ID: task, GatewayID: &gateway, LeaseHash: hash[:]})
		if db.IsNoRows(err) || (err == nil && ct.TestKind != kindVerifierTest) {
			return app.ErrLease
		} else if err != nil {
			return err
		}
		if err := testTokenBasis(ctx, q, org, ct); err != nil {
			return err
		}
		if n, err := q.RecordTestTokenMint(ctx, ct.Attempts, org, ct.TestID); err != nil {
			return err
		} else if n == 0 {
			return app.ErrTestTokensMinted
		}
		m, err := mint(app.VerifierTest{Test: ct.TestID, Connection: ct.ConnectionID, Operation: ct.Operation, Attempt: ct.Attempts})
		if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "connection.test_tokens_minted", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
			Object: &audit.Object{Type: "connection", ID: ct.ConnectionID.String()},
			Details: map[string]string{
				"test_id": ct.TestID.String(), "attempt": strconv.Itoa(int(ct.Attempts)), "operation": ct.Operation,
				"jti": m.FreshID.String(), "mismatch_jti": m.MismatchID.String(),
			},
		}); err != nil {
			return err
		}
		out = m.TestTokens
		return nil
	})
	return out, err
}

// testTokenBasis checks what a test token mint needs besides its lease: the
// connection is ACTIVE and target_enforced, the kill switch is off, and the
// leased operation is the test read of the connection's pinned package.
func testTokenBasis(ctx context.Context, q *dbq.Queries, org ids.OrgID, ct dbq.LeasedConnectionTestRow) error {
	b, err := q.VerifierTestBasis(ctx, org, ct.TestID)
	if err != nil {
		return err
	}
	if b.KillSwitch || b.ConnectionState != "ACTIVE" || b.AccessMode != "target_enforced" {
		return app.ErrTestTokensRefused
	}
	pin, err := q.PinnedPackageRaw(ctx, org, b.Package)
	if db.IsNoRows(err) {
		return app.ErrTestTokensRefused
	} else if err != nil {
		return err
	}
	p, err := manifest.Decode(pin.Raw)
	if err != nil || pin.State == "QUARANTINED" || pin.State == "RETIRED" {
		return app.ErrTestTokensRefused
	}
	if d, ok := p.TestRead(); !ok || d.Operation != ct.Operation {
		return app.ErrTestTokensRefused
	}
	return nil
}

// connectionTest applies a report under a connection_test lease.
func (s *Store) connectionTest(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID,
	task dbq.LeasedConnectionTestRow, r app.Report,
) (app.Applied, error) {
	verifier := task.TestKind == kindVerifierTest
	answered := r.HTTPStatus >= 100 && r.HTTPStatus <= 599
	if len(r.Items) > 0 || (!verifier && len(r.Fields) > 0) || (verifier && answered && !verifierFields(r.Fields)) {
		return app.Applied{}, app.ErrUndeclared
	}
	id, attempt := task.ID, task.Attempts
	o := dbq.InsertObservationParams{
		OrgID: org, ID: ids.NewV7(), Source: "verifier", VerificationID: &id, GatewayID: gateway, Attempt: &attempt,
	}
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
		return out, finishTest(ctx, tx, q, org, gateway, task, "FAILED", "", []testCheck{{
			Check: "TEST_READ", Detail: fmt.Sprintf("The gateway could not make the test read in %d attempts.", task.Attempts),
		}}, nil)
	}
	checks := []testCheck{{
		Check: "TEST_READ", Passed: r.HTTPStatus >= 200 && r.HTTPStatus <= 299,
		Detail: fmt.Sprintf("The target answered HTTP %d to %s.", r.HTTPStatus, task.Operation),
	}}
	if verifier {
		checks = verifierChecks(r.Fields)
	}
	result := "PASSED"
	for _, c := range checks {
		if !c.Passed {
			result = "FAILED"
		}
	}
	if err := q.FinishVerification(ctx, "DONE", org, task.ID); err != nil {
		return app.Applied{}, err
	}
	return out, finishTest(ctx, tx, q, org, gateway, task, "DONE", result, checks, o.ResponseDigest)
}

// verifierFields reports whether fields are exactly a target_verifier
// test's four requests.
func verifierFields(fields map[string]string) bool {
	if len(fields) != len(verifierRequests) {
		return false
	}
	for _, v := range verifierRequests {
		if _, ok := fields[v.field]; !ok {
			return false
		}
	}
	return true
}

// verifierChecks judges each request of a target_verifier test.
func verifierChecks(fields map[string]string) []testCheck {
	out := make([]testCheck, 0, len(verifierRequests))
	for _, v := range verifierRequests {
		statusText, problem, _ := strings.Cut(fields[v.field], " ")
		status, err := strconv.Atoi(statusText)
		var passed bool
		switch {
		case err != nil:
		case v.status == 0:
			passed = status >= 200 && status <= 299
		default:
			passed = status == v.status && problem == v.problem
		}
		answer := "HTTP " + statusText
		if problem != "" {
			answer += " (" + problem + ")"
		}
		detail := "The target answered " + answer + " to " + v.what
		if v.status == 0 {
			detail += "; it must let it through."
		} else {
			detail += fmt.Sprintf("; its verifier must refuse it with %d %s.", v.status, v.problem)
		}
		out = append(out, testCheck{Check: v.check, Passed: passed, Detail: detail})
	}
	return out
}

// finishTest records a test's end and audits it as the gateway.
func finishTest(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, task dbq.LeasedConnectionTestRow,
	state, result string, checks []testCheck, digest []byte,
) error {
	raw, err := json.Marshal(checks, json.Deterministic(true))
	if err != nil {
		return err
	}
	p := dbq.FinishConnectionTestParams{
		State: state, Checks: raw, GatewayID: &gateway, DetailSha256: digest, OrgID: org, ID: task.TestID,
	}
	if result != "" {
		p.Result = &result
	}
	if err := q.FinishConnectionTest(ctx, p); err != nil {
		return err
	}
	details := map[string]string{"kind": task.TestKind, "test_id": task.TestID.String(), "state": state, "operation": task.Operation}
	if result != "" {
		details["result"] = result
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: "connection.tested", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "connection", ID: task.ConnectionID.String()}, Details: details,
	})
	return err
}
