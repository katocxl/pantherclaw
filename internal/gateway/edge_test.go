// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
)

// TestF099_ARawCallThroughTheSandboxEdgeIsTheMCPAction: an agent in the
// sandbox that skips the MCP route and calls the API with a raw HTTPS
// request (curl) reaches, through the edge, the gateway's HTTP face for the
// connection; the package maps it to the same operation, target, params,
// dedupe key and definition as the MCP tool call, so it gets the same
// decision (G0 M9 decision 1, HR-213, HR-214).
func TestF099_ARawCallThroughTheSandboxEdgeIsTheMCPAction(t *testing.T) {
	h := setup(t)
	if r := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", refundArgs), nil); r.code != http.StatusOK || r.body.Result.IsError {
		t.Fatalf("MCP call: %d %+v", r.code, r.body)
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := edge.New(edge.Options{
		GatewayURL: h.url, Routes: []edge.Route{{Host: "payments.example", Connection: "payments"}},
		Run: ids.NewV7().String(), Key: key, Token: testWorkloadToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(e)
	t.Cleanup(ps.Close)
	proxy, _ := url.Parse(ps.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(e.CACertificate())
	agent := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	// What `curl -X POST https://payments.example/v1/refunds -d …` sends, with
	// a credential the agent found; the edge drops it.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://payments.example/v1/refunds",
		strings.NewReader(`{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk_live_found_in_a_dotfile")
	res, err := agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || res.Header.Get("PC-Decision") != "ALLOW" || res.Header.Get("PC-Transaction-Id") == "" {
		t.Fatalf("raw call: %d %v %s", res.StatusCode, res.Header, body)
	}

	s := h.auth.snap()
	if len(s.actions) != 2 {
		t.Fatalf("the Authority decided %d actions", len(s.actions))
	}
	m, x := s.actions[0].Action, s.actions[1].Action
	if m.Operation != x.Operation || m.Target != x.Target || !bytes.Equal(m.Params, x.Params) || m.DedupeKey != x.DedupeKey ||
		m.Definition != x.Definition || m.Channel != "mcp" || x.Channel != "http" {
		t.Fatalf("the routes disagree:\nMCP  %s\nedge %s", s.actions[0].Canonical, s.actions[1].Canonical)
	}
	h.target.mu.Lock()
	defer h.target.mu.Unlock()
	for _, hdr := range h.target.headers {
		if strings.Contains(hdr.Get("Authorization"), "sk_live") {
			t.Fatal("the agent's credential reached the target")
		}
	}
}
