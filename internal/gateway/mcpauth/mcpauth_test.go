// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpauth_test

import (
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/mcpauth"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	gw     = "https://gw.example.test"
	issuer = "https://pc.example.test/orgs/01920000-0000-7000-8000-0000000000a1"
)

type config struct{ c *control.Config }

func (c config) Current() *control.Config { return c.c }

func cfg(on bool) config {
	c := &control.Config{ByName: map[string]*control.Connection{"github": {GatewayConnection: &pb.GatewayConnection{Name: "github"}}}}
	if on {
		c.McpIssuer = issuer
	}
	return config{c}
}

// face records what the MCP face got and answers with status.
type face struct {
	got    *http.Request
	status int
}

func (f *face) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.got = r
	w.WriteHeader(f.status)
}

func token(run string) string {
	p, _ := json.Marshal(map[string]any{"sub": "x", "pap": map[string]any{"run": run, "env": "e"}})
	return "eyJ0eXAiOiJwYXAtbWNwK2p3dCJ9." + base64.RawURLEncoding.EncodeToString(p) + ".sig"
}

func serve(h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, gw+path, strings.NewReader(`{}`))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestHR626_TheOAuthRouteForwardsBearerTokensOnly (G0 M26 D402, D408;
// HR-626): the route is closed while the org's MCP authorization is off;
// it publishes RFC 9728 metadata naming the org's authorization server;
// a call without a bearer token, or with a PAP/1 proof, is challenged; a
// bearer call reaches the MCP face as a proofless token for this route's
// URL in the run the token names, and the face's refusals carry the
// challenge.
// Covers: F912
func TestHR626_TheOAuthRouteForwardsBearerTokensOnly(t *testing.T) {
	f := &face{status: http.StatusOK}
	off := mcpauth.New(f, cfg(false), gw)
	for _, p := range []string{"/mcp-oauth/github", "/.well-known/oauth-protected-resource/mcp-oauth/github"} {
		if w := serve(off, http.MethodPost, p, nil); w.Code != http.StatusNotFound {
			t.Fatalf("%s while off: %d", p, w.Code)
		}
	}
	h := mcpauth.New(f, cfg(true), gw)
	if w := serve(h, http.MethodPost, "/mcp-oauth/slack", map[string]string{"Authorization": "Bearer x"}); w.Code != http.StatusNotFound {
		t.Fatalf("an unknown connection: %d", w.Code)
	}

	w := serve(h, http.MethodGet, "/.well-known/oauth-protected-resource/mcp-oauth/github", nil)
	var md struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil || md.Resource != gw+"/mcp-oauth/github" ||
		len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != issuer {
		t.Fatalf("metadata %d %s", w.Code, w.Body)
	}

	wantChallenge := `Bearer resource_metadata="` + gw + `/.well-known/oauth-protected-resource/mcp-oauth/github"`
	for name, hdr := range map[string]map[string]string{
		"no token":              nil,
		"a PAP/1 token":         {"Authorization": "PAP x"},
		"a bearer + proof":      {"Authorization": "Bearer x", dispatch.HeaderProof: "p"},
		"a token naming no run": {"Authorization": "Bearer " + token("")},
	} {
		f.got = nil
		w := serve(h, http.MethodPost, "/mcp-oauth/github", hdr)
		if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), wantChallenge) || f.got != nil {
			t.Fatalf("%s: %d %q forwarded=%v", name, w.Code, w.Header().Get("WWW-Authenticate"), f.got != nil)
		}
	}

	run := ids.NewV7().String()
	tok := token(run)
	w = serve(h, http.MethodPost, "/mcp-oauth/github", map[string]string{"Authorization": "Bearer " + tok, dispatch.HeaderRunID: ids.NewV7().String()})
	if w.Code != http.StatusOK || f.got == nil {
		t.Fatalf("bearer call: %d", w.Code)
	}
	if f.got.URL.Path != "/mcp/github" || f.got.Header.Get("Authorization") != "PAP "+tok || f.got.Header.Get(dispatch.HeaderProof) != "" ||
		f.got.Header.Get(dispatch.HeaderRunID) != run {
		t.Fatalf("forwarded %s %q run %q", f.got.URL.Path, f.got.Header.Get("Authorization"), f.got.Header.Get(dispatch.HeaderRunID))
	}

	f.status = http.StatusUnauthorized
	w = serve(h, http.MethodPost, "/mcp-oauth/github", map[string]string{"Authorization": "Bearer " + tok})
	if w.Header().Get("WWW-Authenticate") != wantChallenge+`, error="invalid_token"` {
		t.Fatalf("refusal challenge %q", w.Header().Get("WWW-Authenticate"))
	}
}
