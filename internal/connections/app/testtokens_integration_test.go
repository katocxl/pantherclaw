// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/connections/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// jtiOf is an action token's id, unverified.
func jtiOf(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[min(1, len(parts)-1)])
	var c struct {
		Jti string `json:"jti"`
	}
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Jti == "" {
		t.Fatalf("token %q", tok)
	}
	return c.Jti
}

// TestHR188_TestTokensAreMintedOncePerAttemptForTheTestReadOnly (HR-188's
// exception, founder decision 2026-10-13): a target_verifier test's gateway
// gets its two test tokens once per lease attempt, only under its own live
// lease, only while the connection is ACTIVE and target_enforced and the
// kill switch is off, and only for its package's test read. Every mint is
// audited, and a target's verifier refuses the tokens for any other
// operation or target, and for a second use.
func TestHR188_TestTokensAreMintedOncePerAttemptForTheTestReadOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.epoch(t)
	tokened, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "tokened", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test/v1/", Gateway: e.gateway,
		AccessMode: app.AccessTargetEnforced,
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := keys.GenerateSigningKey(keys.PurposeActionTokens)
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	signer, _ := reg.Signer(keys.PurposeActionTokens)
	s := &txapp.Service{Store: &pgtransactions.Store{Pool: e.pool}, ActionTokens: signer}
	claim := func() txapp.Lease {
		t.Helper()
		leases, err := s.Claim(ctx, e.org, e.gateway, 16)
		if err != nil || len(leases) != 1 {
			t.Fatalf("leases %+v %v", leases, err)
		}
		return leases[0]
	}
	lease := func() txapp.Lease {
		t.Helper()
		if _, err := e.svc.Test(e.admin, tokened.ID, app.KindVerifierTest); err != nil {
			t.Fatal(err)
		}
		return claim()
	}
	minted := func() int64 {
		return e.int64(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.test_tokens_minted'")
	}

	l := lease()
	if _, err := s.MintTestTokens(ctx, e.org, ids.NewV7(), l.Task, l.Secret); !errors.Is(err, txapp.ErrLease) {
		t.Fatalf("another gateway's mint: %v", err)
	}
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, make([]byte, 32)); !errors.Is(err, txapp.ErrLease) {
		t.Fatalf("a mint without the lease: %v", err)
	}
	first, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret); !errors.Is(err, txapp.ErrTestTokensMinted) {
		t.Fatalf("a second mint in the same attempt: %v", err)
	}
	if n := minted(); n != 1 {
		t.Fatalf("%d mints audited, want 1", n)
	}
	if n := e.int64(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.test_tokens_minted'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'jti' = $1
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'mismatch_jti' = $2
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'attempt' = '1'
		AND convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'operation' = 'payments.account.read'`,
		jtiOf(t, first.Fresh), jtiOf(t, first.Mismatch)); n != 1 {
		t.Fatal("the mint's audit event does not name its tokens, attempt and operation")
	}

	// The next attempt of the same test gets its own mint, once.
	if _, err := s.Report(ctx, e.org, e.gateway, txapp.Report{Task: l.Task, Secret: l.Secret}); err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE pc.verifications SET next_at = now() WHERE id = $1", l.Task)
	l2 := claim()
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret); !errors.Is(err, txapp.ErrLease) {
		t.Fatalf("a mint under the first attempt's lease: %v", err)
	}
	tk, err := s.MintTestTokens(ctx, e.org, e.gateway, l2.Task, l2.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l2.Task, l2.Secret); !errors.Is(err, txapp.ErrTestTokensMinted) {
		t.Fatalf("a second mint in the second attempt: %v", err)
	}
	if n := minted(); n != 2 {
		t.Fatalf("%d mints audited, want 2", n)
	}

	// A target's verifier lets the fresh token through only for the test
	// read of this connection, once.
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		b, _ := reg.JWKS()
		_, _ = w.Write(b)
	}))
	t.Cleanup(jwks.Close)
	v := &payments.ActionVerifier{JWKSURL: jwks.URL, Audience: tokened.ID.String()}
	verify := func(tok, body string, want payments.Want) error {
		r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/v1/account", nil)
		r.Header.Set(payments.HeaderAction, tok)
		return v.Verify(ctx, r, []byte(body), want)
	}
	read := payments.Want{Operation: "payments.account.read", TargetType: defs.ConnectionTarget, TargetID: tokened.ID.String()}
	refundBody := `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
	for name, tc := range map[string]struct {
		tok, body string
		want      payments.Want
	}{
		"a refund":           {tk.Fresh, "", payments.Want{Operation: "payments.refund.create", TargetType: "payments.charge", TargetID: "ch_1"}},
		"a refund's body":    {tk.Fresh, refundBody, payments.Want{Operation: "payments.refund.create", TargetType: "payments.charge", TargetID: "ch_1"}},
		"another connection": {tk.Fresh, "", payments.Want{Operation: read.Operation, TargetType: read.TargetType, TargetID: ids.NewV7().String()}},
		"the mismatch token": {tk.Mismatch, "", read},
	} {
		if err := verify(tc.tok, tc.body, tc.want); !errors.Is(err, payments.ErrActionTokenInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := verify(tk.Fresh, "", read); err != nil {
		t.Fatalf("the test read: %v", err)
	}
	if err := verify(tk.Fresh, "", read); !errors.Is(err, payments.ErrActionTokenReplay) {
		t.Fatalf("the test read again: %v", err)
	}

	// Under the kill switch, on a connection that is no longer
	// target_enforced, and for a leased operation that is not the package's
	// test read, nothing is minted.
	l3 := lease()
	e.exec(t, "UPDATE pc.org_containment SET kill_switch = true, engaged_by = 'test', engaged_at = now() WHERE org_id = $1", e.org)
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l3.Task, l3.Secret); !errors.Is(err, txapp.ErrTestTokensRefused) {
		t.Fatalf("a mint under the kill switch: %v", err)
	}
	e.exec(t, "UPDATE pc.org_containment SET kill_switch = false, engaged_by = NULL, engaged_at = NULL WHERE org_id = $1", e.org)
	e.exec(t, "UPDATE pc.connections SET access_mode = 'agent_held' WHERE id = $1", tokened.ID)
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l3.Task, l3.Secret); !errors.Is(err, txapp.ErrTestTokensRefused) {
		t.Fatalf("a mint for an agent_held connection: %v", err)
	}
	e.exec(t, "UPDATE pc.connections SET access_mode = 'target_enforced' WHERE id = $1", tokened.ID)
	request, err := json.Marshal(app.TestReadRequest{
		Mode: app.VerifierTestMode, Target: actionir.Target{Type: defs.ConnectionTarget, ID: tokened.ID.String()}, Params: map[string]string{},
	}, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	refund, task := "payments.refund.create", ids.NewV7()
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertConnectionTestTask(ctx, dbq.InsertConnectionTestTaskParams{
			OrgID: e.org, ID: task, ConnectionID: tokened.ID, Operation: refund, Request: request,
		}); err != nil {
			return err
		}
		_, err := q.InsertLeasedConnectionTest(ctx, dbq.InsertLeasedConnectionTestParams{
			OrgID: e.org, ID: ids.NewV7(), ConnectionID: tokened.ID, Kind: app.KindVerifierTest, VerificationID: &task,
			Operation: &refund, RequestedBy: "test",
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	l4 := claim()
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l4.Task, l4.Secret); !errors.Is(err, txapp.ErrTestTokensRefused) {
		t.Fatalf("a mint for a refund: %v", err)
	}
	if n := minted(); n != 2 {
		t.Fatalf("%d mints audited after the refusals, want 2", n)
	}
}

// tokenEnv is an org with a target_enforced connection and the
// verification service that mints its test tokens.
type tokenEnv struct {
	*env
	conn app.Connection
	s    *txapp.Service
}

func newTokenEnv(t *testing.T) tokenEnv {
	t.Helper()
	e := newEnv(t)
	e.epoch(t)
	conn, err := e.svc.Create(e.admin, app.CreateInput{
		Name: "tokened", Kind: app.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test/v1/", Gateway: e.gateway,
		AccessMode: app.AccessTargetEnforced,
	})
	if err != nil {
		t.Fatal(err)
	}
	k, err := keys.GenerateSigningKey(keys.PurposeActionTokens)
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	signer, _ := reg.Signer(keys.PurposeActionTokens)
	return tokenEnv{env: e, conn: conn, s: &txapp.Service{Store: &pgtransactions.Store{Pool: e.pool}, ActionTokens: signer}}
}

// lease asks for a target_verifier test and claims its lease.
func (e tokenEnv) lease(t *testing.T) (app.TestResult, txapp.Lease) {
	t.Helper()
	r, err := e.svc.Test(e.admin, e.conn.ID, app.KindVerifierTest)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := e.s.Claim(context.Background(), e.org, e.gateway, 16)
	if err != nil || len(leases) != 1 {
		t.Fatalf("leases %+v %v", leases, err)
	}
	return r, leases[0]
}

// lifeOf is an action token's iat and exp, unverified.
func lifeOf(t *testing.T, tok string) (iat, exp int64) {
	t.Helper()
	parts := strings.Split(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[min(1, len(parts)-1)])
	var c struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Exp == 0 {
		t.Fatalf("token %q", tok)
	}
	return c.Iat, c.Exp
}

// TestHR188_ATestTokenDoesNotOutliveItsLease: a test token expires no later
// than the lease it was minted under, sooner than an action token's 60
// seconds, so it is not valid after its lease ended, alongside the next
// attempt's tokens.
func TestHR188_ATestTokenDoesNotOutliveItsLease(t *testing.T) {
	e := newTokenEnv(t)
	_, l := e.lease(t)
	tk, err := e.s.MintTestTokens(context.Background(), e.org, e.gateway, l.Task, l.Secret)
	if err != nil {
		t.Fatal(err)
	}
	leaseEnd := e.int64(t, "SELECT floor(extract(epoch FROM lease_expires_at))::bigint FROM pc.verifications WHERE id = $1", l.Task)
	for name, tok := range map[string]string{"fresh": tk.Fresh, "mismatch": tk.Mismatch} {
		if iat, exp := lifeOf(t, tok); exp > leaseEnd || exp >= iat+60 {
			t.Errorf("the %s token lives from %d to %d; its lease ends at %d", name, iat, exp, leaseEnd)
		}
	}
}

// runOut makes a lease's time run out, still LEASED until it is released.
func (e tokenEnv) runOut(t *testing.T, task ids.UUID) {
	t.Helper()
	e.dbt.AdminExec(t, `UPDATE pc.verifications SET leased_at = now() - interval '20 seconds', lease_expires_at = now() - interval '1 second'
		WHERE id = $1 AND state = 'LEASED'`, task)
}

// TestHR188_ATestIsLeasedAndTokenedAtMostThreeTimes: a gateway that gets a
// test's tokens and never reports gets a new lease, and new tokens, after
// its lease runs out, but only three times: after the third lease runs
// out, the test could not run, and nothing leases it again, even when its
// task is put back.
func TestHR188_ATestIsLeasedAndTokenedAtMostThreeTimes(t *testing.T) {
	e := newTokenEnv(t)
	ctx := context.Background()
	r, l := e.lease(t)
	for attempt := 1; ; attempt++ {
		if l.Attempt != attempt {
			t.Fatalf("lease %d is attempt %d", attempt, l.Attempt)
		}
		if _, err := e.s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		e.runOut(t, l.Task)
		if _, err := e.s.Expire(ctx, e.org); err != nil {
			t.Fatal(err)
		}
		leases, err := e.s.Claim(ctx, e.org, e.gateway, 16)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 3 {
			if len(leases) != 0 {
				t.Fatalf("%d fourth leases", len(leases))
			}
			break
		}
		if len(leases) != 1 {
			t.Fatalf("after attempt %d: leases %+v", attempt, leases)
		}
		l = leases[0]
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.test_tokens_minted'"); n != 3 {
		t.Fatalf("%d mints, want 3", n)
	}
	if st, _, checks, _ := e.testRow(t, r.ID); st != "FAILED" || len(checks) != 1 || checks[0].Passed ||
		checks[0].Detail != "No gateway reported the test read in 3 attempts." {
		t.Fatalf("test %s %+v", st, checks)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.verifications WHERE id = $1 AND state = 'EXPIRED' AND attempts = 3", l.Task); n != 1 {
		t.Fatal("the task did not end EXPIRED after three attempts")
	}
	e.dbt.AdminExec(t, "UPDATE pc.verifications SET state = 'PENDING', finished_at = NULL, next_at = now() WHERE id = $1", l.Task)
	if leases, err := e.s.Claim(ctx, e.org, e.gateway, 16); err != nil || len(leases) != 0 {
		t.Fatalf("a task leased three times leased again: %d leases, %v", len(leases), err)
	}
}

// TestHR188_TestTokensNeedTheirLeaseConnectionAndPackage: under a lease it
// holds, the gateway gets no tokens while the connection is quarantined or
// retired, or while the pinned package version is quarantined or retired.
// Of several mints at once for the same attempt, exactly one gets tokens.
// A lease whose time ran out gets none, even before it is released.
func TestHR188_TestTokensNeedTheirLeaseConnectionAndPackage(t *testing.T) {
	e := newTokenEnv(t)
	ctx := context.Background()
	_, l := e.lease(t)
	mint := func(l txapp.Lease) error {
		_, err := e.s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret)
		return err
	}
	for _, state := range []string{"QUARANTINED", "RETIRED"} {
		e.exec(t, `UPDATE pc.connections SET state = $2, quarantine_reason = CASE WHEN $2 = 'QUARANTINED' THEN 'test' END
			WHERE id = $1`, e.conn.ID, state)
		if err := mint(l); !errors.Is(err, txapp.ErrTestTokensRefused) {
			t.Errorf("a %s connection: %v", state, err)
		}
		e.exec(t, "UPDATE pc.connections SET state = 'ACTIVE', quarantine_reason = NULL WHERE id = $1", e.conn.ID)
	}
	pin := func(state string) {
		e.exec(t, `UPDATE pc.package_versions SET state = $2 WHERE id = (SELECT p.version_id FROM pc.package_pins p
			JOIN pc.tool_packages k ON k.org_id = p.org_id AND k.id = p.package_id WHERE k.name = $1)`, mockpayments.Name, state)
	}
	for _, state := range []string{"QUARANTINED", "RETIRED"} {
		pin(state)
		if err := mint(l); !errors.Is(err, txapp.ErrTestTokensRefused) {
			t.Errorf("a %s package version: %v", state, err)
		}
		pin("ACTIVE")
	}
	minted := func() int64 {
		return e.int64(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.connection.test_tokens_minted'")
	}
	if n := minted(); n != 0 {
		t.Fatalf("%d mints after the refusals", n)
	}

	errs := make([]error, 4)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			<-start
			errs[i] = mint(l)
		})
	}
	close(start)
	wg.Wait()
	got := 0
	for _, err := range errs {
		switch {
		case err == nil:
			got++
		case !errors.Is(err, txapp.ErrTestTokensMinted):
			t.Errorf("a concurrent mint: %v", err)
		}
	}
	if n := minted(); got != 1 || n != 1 {
		t.Fatalf("%d of %d concurrent mints got tokens, %d audited; want 1", got, len(errs), n)
	}

	_, l2 := e.lease(t)
	e.runOut(t, l2.Task)
	if err := mint(l2); !errors.Is(err, txapp.ErrLease) {
		t.Fatalf("a lease whose time ran out: %v", err)
	}
	if n := e.int64(t, "SELECT count(*) FROM pc.verifications WHERE id = $1 AND state = 'LEASED'", l2.Task); n != 1 {
		t.Fatal("the lease was released; the check needs it LEASED")
	}
}

// TestHR188_AMintsAuditEventNamesTokenIdsNeverTokens: the audit event of a
// mint carries the test, attempt, operation and the two token ids, and no
// part of either token.
func TestHR188_AMintsAuditEventNamesTokenIdsNeverTokens(t *testing.T) {
	e := newTokenEnv(t)
	r, l := e.lease(t)
	tk, err := e.s.MintTestTokens(context.Background(), e.org, e.gateway, l.Task, l.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE kind = 'audit.connection.test_tokens_minted'").
			Scan(&body)
	}); err != nil {
		t.Fatal(err)
	}
	for name, tok := range map[string]string{"fresh": tk.Fresh, "mismatch": tk.Mismatch} {
		for _, part := range strings.Split(tok, ".") {
			if strings.Contains(body, part) {
				t.Errorf("the audit event carries part of the %s token", name)
			}
		}
	}
	var ev struct {
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"test_id": r.ID.String(), "attempt": "1", "operation": "payments.account.read",
		"jti": jtiOf(t, tk.Fresh), "mismatch_jti": jtiOf(t, tk.Mismatch),
	}
	if !maps.Equal(ev.Details, want) {
		t.Fatalf("details %v, want %v", ev.Details, want)
	}
}

// TestHR188_WithoutAContainmentRowNoTestTokens: without the org's
// containment row, whether the kill switch is on is unknown, and the mint
// is refused; with the row back, it is not.
func TestHR188_WithoutAContainmentRowNoTestTokens(t *testing.T) {
	e := newTokenEnv(t)
	ctx := context.Background()
	_, l := e.lease(t)
	e.dbt.AdminExec(t, "DELETE FROM pc.org_containment WHERE org_id = $1", e.org)
	if _, err := e.s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret); !errors.Is(err, txapp.ErrTestTokensRefused) {
		t.Fatalf("a mint without a containment row: %v", err)
	}
	e.epoch(t)
	if _, err := e.s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret); err != nil {
		t.Fatalf("a mint with the row back: %v", err)
	}
}
