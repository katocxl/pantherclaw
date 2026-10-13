// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// tokenClaims are the claims of an action token, unverified (the test
// checks what it binds; the signature is the signer's).
type tokenClaims struct {
	Aud string `json:"aud"`
	Pap struct {
		BH     string `json:"bh"`
		Op     string `json:"op"`
		Target struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"target"`
	} `json:"pap"`
}

func claimsOf(t *testing.T, tok string) tokenClaims {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c tokenClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// verifierAnswers are what a target whose verifier works answers to a
// target_verifier test's four requests.
func verifierAnswers() map[string]string {
	return map[string]string{
		"/missing": "401 urn:pantherclaw:action-token:missing", "/body_mismatch": "401 urn:pantherclaw:action-token:body_mismatch",
		"/fresh": "200", "/replayed": "409 urn:pantherclaw:action-token:replayed",
	}
}

// TestF354_ATargetVerifierTestIsJudgedOnTheVerifiersOwnAnswers (N15): a
// target_verifier test runs only on a target_enforced connection and
// records the test read's operation. Under its live lease the gateway gets
// test-purpose action tokens for that read only: one binding its empty
// body, one binding another body; no other lease gets any. The test passes
// only when the target refused the request without a token, the token
// bound to another body and the replayed token with its verifier's own
// problem documents, and let the fresh token through.
func TestF354_ATargetVerifierTestIsJudgedOnTheVerifiersOwnAnswers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.epoch(t)
	held := e.payments(t, "payments")
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

	if _, err := e.svc.Test(e.admin, held.ID, app.KindVerifierTest); !errors.Is(err, app.ErrVerifierTest) {
		t.Fatalf("a target_verifier test of a held connection: %v", err)
	}
	if _, err := e.svc.Test(e.admin, tokened.ID, app.KindReadTest); !errors.Is(err, app.ErrReadTest) {
		t.Fatalf("a read test of a target_enforced connection: %v", err)
	}
	run := func(answers map[string]string) (app.TestResult, string, []app.Check) {
		t.Helper()
		r, err := e.svc.Test(e.admin, tokened.ID, app.KindVerifierTest)
		if err != nil || r.Kind != app.KindVerifierTest || r.Operation != "payments.account.read" || r.State != "PENDING" {
			t.Fatalf("target_verifier test %+v %v", r, err)
		}
		leases, err := s.Claim(ctx, e.org, e.gateway, 16)
		if err != nil || len(leases) != 1 {
			t.Fatalf("leases %+v %v", leases, err)
		}
		l := leases[0]
		var req app.TestReadRequest
		if err := json.Unmarshal(l.Request, &req, json.RejectUnknownMembers(true)); err != nil || req.Mode != app.VerifierTestMode {
			t.Fatalf("request %s %v", l.Request, err)
		}
		if _, err := s.MintTestTokens(ctx, e.org, ids.NewV7(), l.Task, l.Secret); !errors.Is(err, txapp.ErrLease) {
			t.Fatalf("another gateway's tokens: %v", err)
		}
		if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, make([]byte, 32)); !errors.Is(err, txapp.ErrLease) {
			t.Fatalf("tokens without the lease: %v", err)
		}
		tk, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret)
		if err != nil {
			t.Fatal(err)
		}
		empty := sha256.Sum256(nil)
		fresh, other := claimsOf(t, tk.Fresh), claimsOf(t, tk.Mismatch)
		if fresh.Aud != tokened.ID.String() || fresh.Pap.Op != "payments.account.read" || fresh.Pap.Target.Type != "pc.connection" ||
			fresh.Pap.Target.ID != tokened.ID.String() || fresh.Pap.BH != hex.EncodeToString(empty[:]) || other.Pap.BH == fresh.Pap.BH ||
			other.Pap.Op != fresh.Pap.Op {
			t.Fatalf("tokens bind %+v and %+v", fresh, other)
		}
		if _, err := s.Report(ctx, e.org, e.gateway, txapp.Report{
			Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Fields: map[string]string{"/fresh": "200"},
		}); !errors.Is(err, txapp.ErrUndeclared) {
			t.Fatalf("a report without every request: %v", err)
		}
		if _, err := s.Report(ctx, e.org, e.gateway, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Fields: answers}); err != nil {
			t.Fatal(err)
		}
		st, res, checks, _ := e.testRow(t, r.ID)
		if st != "DONE" || len(checks) != 4 {
			t.Fatalf("test %s %+v", st, checks)
		}
		return r, res, checks
	}

	passed, res, checks := run(verifierAnswers())
	for _, c := range checks {
		if !c.Passed {
			t.Errorf("check %+v", c)
		}
	}
	if res != app.TestPassed || e.int64(t, `SELECT count(*) FROM pc.connection_tests WHERE id = $1 AND kind = 'target_verifier'
		AND operation = 'payments.account.read' AND result = 'PASSED'`, passed.ID) != 1 {
		t.Fatalf("a working verifier: %s", res)
	}
	replayed := verifierAnswers()
	replayed["/replayed"] = "200"
	if _, res, checks := run(replayed); res != app.TestFailed || checks[3].Passed || !strings.Contains(checks[3].Detail, "HTTP 200") {
		t.Fatalf("a replay let through: %s %+v", res, checks)
	}
	plain := verifierAnswers()
	plain["/missing"] = "401"
	if _, res, checks := run(plain); res != app.TestFailed || checks[0].Passed {
		t.Fatalf("a refusal that is not the verifier's own: %s %+v", res, checks)
	}

	_, l := e.readTest(t, s, held.ID)
	if _, err := s.MintTestTokens(ctx, e.org, e.gateway, l.Task, l.Secret); !errors.Is(err, txapp.ErrLease) {
		t.Fatalf("tokens for a read test: %v", err)
	}
}
