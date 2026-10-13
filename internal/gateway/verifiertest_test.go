// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
)

// verifierTarget answers the test read as a target whose PantherClaw
// verifier works (PAP-1 §10, the SDK verifiers' problem documents), or,
// when plain, refuses without them. It checks only what a test exercises:
// a token, its body hash and its single use.
func verifierTarget(n *atomic.Int32, plain bool) func(*harness) {
	var mu sync.Mutex
	seen := map[string]bool{}
	refuse := func(w http.ResponseWriter, status int, code string) {
		if plain {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"refused"}`)
			return
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"type":"urn:pantherclaw:action-token:`+code+`","title":"action token refused","code":"`+code+`"}`)
	}
	return func(h *harness) {
		h.conn.AccessMode = "target_enforced"
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			body, _ := io.ReadAll(r.Body)
			tok := r.Header.Get("PAP-Action")
			if r.Method != http.MethodGet || r.URL.Path != "/v1/account" {
				http.NotFound(w, r)
				return
			}
			if tok == "" {
				refuse(w, http.StatusUnauthorized, "missing")
				return
			}
			var c struct {
				Jti string `json:"jti"`
				Pap struct {
					BH string `json:"bh"`
				} `json:"pap"`
			}
			parts := strings.Split(tok, ".")
			raw, _ := base64.RawURLEncoding.DecodeString(parts[min(1, len(parts)-1)])
			sum := sha256.Sum256(body)
			if json.Unmarshal(raw, &c) != nil || c.Pap.BH != hex.EncodeToString(sum[:]) {
				refuse(w, http.StatusUnauthorized, "body_mismatch")
				return
			}
			mu.Lock()
			replayed := seen[c.Jti]
			seen[c.Jti] = true
			mu.Unlock()
			if replayed {
				refuse(w, http.StatusConflict, "replayed")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"acct_1"}`)
		}))
		h.targetURL = ts.URL
	}
}

// fakeToken is an unsigned stand-in for an action token binding body.
func fakeToken(jti, body string) string {
	sum := sha256.Sum256([]byte(body))
	payload := `{"jti":"` + jti + `","pap":{"bh":"` + hex.EncodeToString(sum[:]) + `"}}`
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

func verifierLease(tokens func(context.Context) (dispatch.TestTokens, error)) dispatch.Lease {
	return dispatch.Lease{
		Purpose: "connection_test", Operation: "payments.account.read", Tokens: tokens,
		Request: []byte(`{"mode":"target_verifier","target":{"type":"pc.connection","id":"` + connID + `"},"params":{}}`),
	}
}

func testTokens(context.Context) (dispatch.TestTokens, error) {
	return dispatch.TestTokens{Fresh: fakeToken("t1", ""), Mismatch: fakeToken("t2", "another body")}, nil
}

// TestF354_ATargetVerifierTestSendsTheTestReadFourTimes (N15): on a
// target_enforced connection, a target_verifier lease sends the package's
// test read without a token, with the token bound to another body, with the
// fresh token and with it again, and reports each answer with the
// verifier's problem type; a refusal that is not one carries none. It
// needs a target_enforced connection and the lease's tokens, and sends
// nothing otherwise.
func TestF354_ATargetVerifierTestSendsTheTestReadFourTimes(t *testing.T) {
	ctx := context.Background()
	var sent atomic.Int32
	h := setup(t, verifierTarget(&sent, false))
	o, err := h.gw.engine.VerifyEffect(ctx, h.conn, verifierLease(testTokens))
	want := map[string]string{
		"/missing": "401 urn:pantherclaw:action-token:missing", "/body_mismatch": "401 urn:pantherclaw:action-token:body_mismatch",
		"/fresh": "200", "/replayed": "409 urn:pantherclaw:action-token:replayed",
	}
	if err != nil || o.HTTPStatus != http.StatusOK || len(o.Digest) != 32 || len(o.Fields) != len(want) || sent.Load() != 4 {
		t.Fatalf("observation %+v %v (%d requests)", o, err, sent.Load())
	}
	for k, v := range want {
		if o.Fields[k] != v {
			t.Errorf("%s = %q, want %q", k, o.Fields[k], v)
		}
	}

	var plainSent atomic.Int32
	plain := setup(t, verifierTarget(&plainSent, true))
	if o, err := plain.gw.engine.VerifyEffect(ctx, plain.conn, verifierLease(testTokens)); err != nil || o.Fields["/missing"] != "403" {
		t.Fatalf("a plain refusal: %+v %v", o, err)
	}

	var none atomic.Int32
	open := setup(t, simTarget(nil, &none), func(h *harness) { h.conn.AccessMode = "none" })
	if _, err := open.gw.engine.VerifyEffect(ctx, open.conn, verifierLease(testTokens)); !errors.Is(err, dispatch.ErrNotReviewedRead) {
		t.Fatalf("a connection that is not target_enforced: %v", err)
	}
	if _, err := h.gw.engine.VerifyEffect(ctx, h.conn, verifierLease(nil)); !errors.Is(err, dispatch.ErrNotReviewedRead) {
		t.Fatalf("a lease without tokens: %v", err)
	}
	if n := sent.Load() + none.Load(); n != 4 {
		t.Fatalf("refused leases sent %d requests", n-4)
	}
}
