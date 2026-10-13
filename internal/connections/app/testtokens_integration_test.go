// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
