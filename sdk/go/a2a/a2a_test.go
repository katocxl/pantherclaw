// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package a2a_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/a2a"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
	"github.com/katocxl/pantherclaw/sdk/go/verifier"
)

const (
	issuer   = "https://pc.example.test"
	audience = "https://gw.example.test/a2a/peer"
	run      = "0190f3b4-7c2e-7aaa-8bbb-000000000042"
)

type minter struct {
	key ed25519.PrivateKey
	kid string
	srv *httptest.Server
}

func newMinter(t *testing.T) *minter {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &minter{key: key, kid: verifier.ActionTokenKID(pub)}
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub), "kid": m.kid, "alg": "EdDSA",
	}}})
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(jwks) }))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *minter) token(t *testing.T, body []byte, op, peerRun string) string {
	t.Helper()
	sum := sha256.Sum256(body)
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": issuer, "aud": audience, "jti": hex.EncodeToString(sum[:8]) + op + peerRun, "iat": now, "exp": now + 30,
		"pap": map[string]any{"v": 1, "txn": "t", "act": "a", "bh": hex.EncodeToString(sum[:]), "op": op,
			"target": map[string]string{"type": "a2a.agent", "id": "peer"}},
	}
	if peerRun != "" {
		claims["pc_peer_run"] = peerRun
	}
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": m.kid, "typ": verifier.TypeActionToken})
	p, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	return input + "." + enc.EncodeToString(ed25519.Sign(m.key, []byte(input)))
}

func (m *minter) verifier(t *testing.T) *verifier.Verifier {
	t.Helper()
	v, err := verifier.New(verifier.Config{JWKSURL: m.srv.URL, Issuer: issuer, Audience: audience, Store: verifier.NewMemoryStore(0, time.Now().Add(-time.Hour))})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestHR325_PeerRunFromTheGatewaysToken: a message the gateway sent names
// its peer run; a direct message, another request's token, a replay, a
// token for another operation and one without a peer run are refused.
func TestHR325_PeerRunFromTheGatewaysToken(t *testing.T) {
	m := newMinter(t)
	v := m.verifier(t)
	body := []byte(`{"jsonrpc":"2.0","id":"t","method":"SendMessage","params":{}}`)
	h := http.Header{}
	h.Set(pap.HeaderAction, m.token(t, body, a2a.Operation, run))
	got, err := a2a.PeerRun(t.Context(), v, h, body)
	if err != nil || got != run {
		t.Fatalf("peer run %q: %v", got, err)
	}
	if _, err := a2a.PeerRun(t.Context(), v, h, body); verifier.CodeOf(err) != verifier.Replayed {
		t.Fatalf("replay: %v", err)
	}
	if _, err := a2a.PeerRun(t.Context(), v, http.Header{}, body); verifier.CodeOf(err) != verifier.Missing {
		t.Fatalf("direct message: %v", err)
	}
	h.Set(pap.HeaderAction, m.token(t, body, a2a.Operation, run))
	if _, err := a2a.PeerRun(t.Context(), v, h, append(body, ' ')); verifier.CodeOf(err) != verifier.BodyMismatch {
		t.Fatalf("other body: %v", err)
	}
	h.Set(pap.HeaderAction, m.token(t, body, "payments.refund.create", run))
	if _, err := a2a.PeerRun(t.Context(), v, h, body); verifier.CodeOf(err) != verifier.OperationMismatch {
		t.Fatalf("other operation: %v", err)
	}
	other := []byte(`{"other":1}`)
	h.Set(pap.HeaderAction, m.token(t, other, a2a.Operation, ""))
	if _, err := a2a.PeerRun(t.Context(), v, h, other); !errors.Is(err, a2a.ErrNoPeerRun) {
		t.Fatalf("no peer run: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	m := newMinter(t)
	var seen string
	h := a2a.Middleware(m.verifier(t), 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = a2a.RunFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	body := []byte(`{"message":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/message:send", bytes.NewReader(body))
	req.Header.Set(pap.HeaderAction, m.token(t, body, a2a.Operation, run))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent || seen != run {
		t.Fatalf("%d %q", w.Code, seen)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/message:send", bytes.NewReader(body)))
	if w.Code == http.StatusNoContent {
		t.Fatal("a message without a token reached the agent")
	}
}
