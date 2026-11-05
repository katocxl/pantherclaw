// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpauth_test

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/mcpauth"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR700_TheRelayForwardsAProofOnlyUnderTheDPoPScheme (G0 M30 D913,
// HR-700): under "Authorization: DPoP" the route forwards the client's one
// DPoP proof as PC-MCP-DPoP and never a copy the client sent itself; under
// the Bearer scheme no proof is forwarded at all, so the Authority refuses a
// bound token sent as a bearer token. The DPoP scheme without exactly one
// proof is challenged with invalid_dpop_proof and forwards nothing.
func TestHR700_TheRelayForwardsAProofOnlyUnderTheDPoPScheme(t *testing.T) {
	f := &face{status: http.StatusOK}
	h := mcpauth.New(f, cfg(true), gw)
	tok := token(ids.NewV7().String())

	// Passing: the DPoP scheme forwards the proof, not the spoofed copy.
	w := serve(h, http.MethodPost, "/mcp-oauth/github", map[string]string{
		"Authorization": "DPoP " + tok, mcpauth.HeaderDPoP: "the.real.proof", dispatch.HeaderMcpDPoP: "spoofed.copy.x",
	})
	if w.Code != http.StatusOK || f.got == nil {
		t.Fatalf("DPoP call: %d", w.Code)
	}
	if f.got.Header.Get("Authorization") != "PAP "+tok || f.got.Header.Get(dispatch.HeaderMcpDPoP) != "the.real.proof" ||
		f.got.Header.Get(mcpauth.HeaderDPoP) != "" {
		t.Fatalf("forwarded %q proof %q dpop %q", f.got.Header.Get("Authorization"), f.got.Header.Get(dispatch.HeaderMcpDPoP),
			f.got.Header.Get(mcpauth.HeaderDPoP))
	}

	// Refusing: the Bearer scheme forwards no proof, whatever the client sent.
	f.got = nil
	w = serve(h, http.MethodPost, "/mcp-oauth/github", map[string]string{
		"Authorization": "Bearer " + tok, mcpauth.HeaderDPoP: "the.real.proof", dispatch.HeaderMcpDPoP: "spoofed.copy.x",
	})
	if w.Code != http.StatusOK || f.got == nil || f.got.Header.Get(dispatch.HeaderMcpDPoP) != "" || f.got.Header.Get(mcpauth.HeaderDPoP) != "" {
		t.Fatalf("a bearer call forwarded a proof: %d %v", w.Code, f.got)
	}

	// Refusing: the DPoP scheme with no proof, or with two.
	for name, proofs := range map[string][]string{"no proof": nil, "two proofs": {"a.b.c", "d.e.f"}} {
		f.got = nil
		r := httptest.NewRequest(http.MethodPost, gw+"/mcp-oauth/github", strings.NewReader(`{}`))
		r.Header.Set("Authorization", "DPoP "+tok)
		for _, p := range proofs {
			r.Header.Add(mcpauth.HeaderDPoP, p)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized || f.got != nil ||
			!strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "DPoP ") ||
			!strings.HasSuffix(rec.Header().Get("WWW-Authenticate"), `error="invalid_dpop_proof"`) {
			t.Fatalf("%s: %d %q forwarded=%v", name, rec.Code, rec.Header().Get("WWW-Authenticate"), f.got != nil)
		}
	}
}

// TestHR702_AMissingNonceIsAnsweredWithTheCurrentNonce (G0 M30 D913, HR-702):
// when the Authority refuses a DPoP call for want of a live nonce, the
// client gets use_dpop_nonce and the nonce in DPoP-Nonce; any other refusal
// of a DPoP call is invalid_token under the DPoP challenge, with no nonce
// invented. Metadata advertises the proof algorithms and that bound tokens
// are not required (D914, FD4).
func TestHR702_AMissingNonceIsAnsweredWithTheCurrentNonce(t *testing.T) {
	f := &nonceFace{code: string(pap.CodeUseNonce), nonce: "n-0123456789"}
	h := mcpauth.New(f, cfg(true), gw)
	tok := token(ids.NewV7().String())
	hdr := map[string]string{"Authorization": "DPoP " + tok, mcpauth.HeaderDPoP: "a.b.c"}

	w := serve(h, http.MethodPost, "/mcp-oauth/github", hdr)
	if w.Code != http.StatusUnauthorized || w.Header().Get(mcpauth.HeaderDPoPNonce) != "n-0123456789" ||
		!strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "DPoP ") ||
		!strings.HasSuffix(w.Header().Get("WWW-Authenticate"), `error="use_dpop_nonce"`) {
		t.Fatalf("use_nonce: %d %q nonce %q", w.Code, w.Header().Get("WWW-Authenticate"), w.Header().Get(mcpauth.HeaderDPoPNonce))
	}

	f.code, f.nonce = string(pap.CodeProofReplay), ""
	w = serve(h, http.MethodPost, "/mcp-oauth/github", hdr)
	if w.Code != http.StatusUnauthorized || w.Header().Get(mcpauth.HeaderDPoPNonce) != "" ||
		!strings.HasSuffix(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("replay: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	w = serve(h, http.MethodGet, "/.well-known/oauth-protected-resource/mcp-oauth/github", nil)
	var md struct {
		Algs     []string `json:"dpop_signing_alg_values_supported"`
		Required *bool    `json:"dpop_bound_access_tokens_required"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil || len(md.Algs) != 1 || md.Algs[0] != "EdDSA" || md.Required == nil || *md.Required {
		t.Fatalf("metadata %s", w.Body)
	}
}

// nonceFace refuses every call 401 with the Authority's error code and
// nonce headers.
type nonceFace struct{ code, nonce string }

func (f *nonceFace) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(dispatch.HeaderError, f.code)
	if f.nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, f.nonce)
	}
	w.WriteHeader(http.StatusUnauthorized)
}
