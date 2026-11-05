// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

const refusedKind = "audit.security.workload_proof_refused"

// signedRequest builds a request carrying token and a fresh proof by wl.
func (w *world) signedRequest(t *testing.T, wl workload, token string) app.IdentifyInput {
	t.Helper()
	n, err := w.svc.Nonce(context.Background(), w.org)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"amount":1}`)
	proof, err := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: gatewayURL, Body: body, Token: token, Nonce: n, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return app.IdentifyInput{Request: pap.Request{Method: "POST", URL: gatewayURL, BodySHA256: sha256.Sum256(body), Token: token}, Proof: proof}
}

// refuse runs in through Identify, wants code, and records the refusal as
// the Authority does.
func (w *world) refuse(t *testing.T, in app.IdentifyInput, code pap.Code) {
	t.Helper()
	_, err := w.svc.Identify(context.Background(), w.org, in)
	wantPAP(t, string(code), err, code)
	if err := w.svc.RecordRefusedProof(context.Background(), w.org, in, "gw-1", err); err != nil {
		t.Fatal(err)
	}
}

// TestHR850_RefusedProofsAreIdentityEvents: a replayed proof is recorded
// once as audit.security.workload_proof_refused, with its code, instance,
// agent, key thumbprint and gateway and never the token or the proof; a
// flood within a minute records nothing more, and the next record counts
// what was suppressed; a refusal that is only expiry records nothing.
func TestHR850_RefusedProofsAreIdentityEvents(t *testing.T) {
	w := newWorld(t)
	clk := clock.NewFake(time.Now())
	w.svc = app.New(w.pool, w.reg, issuer, clk)
	wl, inst, agent := w.admitted(t, adomain.ContextCI)
	iss, err := w.token(wl, t, inst, "")
	if err != nil {
		t.Fatal(err)
	}
	in := w.signedRequest(t, wl, iss.Token)
	if _, err := w.svc.Identify(context.Background(), w.org, in); err != nil {
		t.Fatalf("first use: %v", err)
	}
	w.refuse(t, in, pap.CodeProofReplay)
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = '"+refusedKind+"'", w.org); n != 1 {
		t.Fatalf("records after one replay: %d, want 1", n)
	}
	var body string
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT convert_from(body, 'UTF8') FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2",
			w.org, refusedKind).Scan(&body)
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"pap_code":"proof_replay"`, `"instance":"` + inst.Instance.String() + `"`, `"agent":"` + agent.String() + `"`,
		`"jkt":"` + jws.Thumbprint(wl.pub) + `"`, `"gateway":"gw-1"`, `"suppressed":"0"`} {
		if !strings.Contains(body, want) {
			t.Errorf("record lacks %s: %s", want, body)
		}
	}
	for _, part := range append(strings.Split(iss.Token, "."), strings.Split(in.Proof, ".")...) {
		if len(part) > 16 && strings.Contains(body, part) {
			t.Fatalf("the record carries token or proof material: %s", body)
		}
	}

	// A flood within the minute: refused every time, recorded no more.
	for range 5 {
		w.refuse(t, in, pap.CodeProofReplay)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = '"+refusedKind+"'", w.org); n != 1 {
		t.Fatalf("records after a flood: %d, want 1", n)
	}
	clk.Advance(app.RefusalWindow + time.Second)
	w.refuse(t, in, pap.CodeProofReplay)
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = '"+refusedKind+"'"+
		" AND convert_from(body, 'UTF8') LIKE '%\"suppressed\":\"5\"%'", w.org); n != 1 {
		t.Fatal("the next record does not carry the 5 suppressed refusals")
	}

	// Another key with the instance's token: its own code, its own record.
	w.refuse(t, w.signedRequest(t, newWorkload(), iss.Token), pap.CodeKeyMismatch)
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = '"+refusedKind+"'"+
		" AND convert_from(body, 'UTF8') LIKE '%\"pap_code\":\"key_mismatch\"%'", w.org); n != 1 {
		t.Error("a proof by another key was not recorded")
	}

	// Only expiry: refused, logged by the Authority, never recorded.
	before := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = '"+refusedKind+"'", w.org)
	clk.Advance(pap.MaxTokenTTL + time.Minute)
	expired := w.signedRequest(t, wl, iss.Token)
	_, err = w.svc.Identify(context.Background(), w.org, expired)
	wantPAP(t, "expired token", err, pap.CodeTokenExpired)
	if !pap.Stale(err) {
		t.Errorf("an expired token is not stale: %v", err)
	}
	if err := w.svc.RecordRefusedProof(context.Background(), w.org, expired, "gw-1", err); err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = '"+refusedKind+"'", w.org); n != before {
		t.Errorf("an expiry-only refusal was recorded: %d records, want %d", n, before)
	}
}
