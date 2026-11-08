// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestE2E_M35_Exit is M35's exit on the real stack: the federation face
// refuses a browser and an unknown method, a token that is not a
// pap-fed+jwt, and an unknown org has no federation document.
func TestE2E_M35_Exit(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	send := `{"jsonrpc":"2.0","id":"1","method":"SendMessage","params":{}}`
	origin := fedPost(t, s.gateway+"/fed/a2a/pay", send, map[string]string{"Origin": "https://evil.example"})
	if origin.code != http.StatusForbidden || !strings.Contains(origin.body, "PANTHERCLAW_REFUSED") {
		t.Fatalf("origin: %d %s", origin.code, origin.body)
	}
	method := fedPost(t, s.gateway+"/fed/a2a/pay", `{"jsonrpc":"2.0","id":"1","method":"tasks/get","params":{}}`, nil)
	if !strings.Contains(method.body, "FEDERATION_METHOD_NOT_DECIDED") {
		t.Fatalf("method: %d %s", method.code, method.body)
	}
	token := fedPost(t, s.gateway+"/fed/a2a/pay", send, map[string]string{"Authorization": "PAP-Fed not-a-token"})
	if token.code != http.StatusUnauthorized || !strings.Contains(token.body, "PANTHERCLAW_AUTHENTICATION") {
		t.Fatalf("token: %d %s", token.code, token.body)
	}
	docReq, err := http.NewRequest(http.MethodGet, s.apiURL+"/.well-known/pantherclaw/orgs/"+ids.New[ids.Org]().String()+"/federation.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := (&http.Client{Timeout: 30 * time.Second}).Do(docReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = doc.Body.Close() }()
	if doc.StatusCode != http.StatusNotFound {
		b, _ := io.ReadAll(io.LimitReader(doc.Body, 512))
		t.Fatalf("document: %d %s", doc.StatusCode, b)
	}
}

func fedPost(t *testing.T, url, body string, hdr map[string]string) fedResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	return fedResponse{code: res.StatusCode, body: string(b)}
}
