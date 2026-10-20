// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package pep_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/katocxl/pantherclaw/sdk/go/pep"
)

const allowed = `{"decision":true,"context":{"pantherclaw":{"outcome":"allow","coverage":"PARTIAL"}}}`

func allow(map[string]any) (int, string) { return http.StatusOK, allowed }

// TestPEPForwardsOnlyWhatWasEvaluated: only Content-Type, exactly as
// evaluated, and the allow-listed headers reach the target; PAP and PC
// headers in any spelling (an agent's own PAP-Action, PAP_Action,
// PC-Action-Id) never do; an encoded body, a method override and trailers
// are refused before anything is asked (D101 M1).
func TestPEPForwardsOnlyWhatWasEvaluated(t *testing.T) {
	p, u, s := setup(t, "http", allow)
	hdr := map[string]string{}
	for k, v := range agent {
		hdr[k] = v
	}
	hdr["Content-Type"] = "application/json; charset=utf-8"
	hdr["Accept"] = "application/json"
	hdr["PAP_Action"] = "smuggled"
	hdr["PAP-Action"] = "smuggled"
	hdr["X-Custom"] = "not forwarded"
	hdr["Cookie"] = "session=1"
	if resp, body := send(t, s.URL+"/v1/refunds", `{}`, hdr); resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed: %d %s", resp.StatusCode, body)
	}
	got := u.reqs[0].Header
	if got.Get("Content-Type") != "application/json; charset=utf-8" || got.Get("Accept") != "application/json" {
		t.Fatalf("allow-listed headers: %v", got)
	}
	for k := range got {
		lk := strings.ToLower(strings.ReplaceAll(k, "_", "-"))
		if strings.HasPrefix(lk, "pap-") || strings.HasPrefix(lk, "pc-") || lk == "x-custom" || lk == "cookie" {
			t.Errorf("forwarded %s: %v", k, got[k])
		}
	}
	ct := p.got[0]["resource"].(map[string]any)["properties"].(map[string]any)["content_type"]
	if ct != "application/json; charset=utf-8" {
		t.Fatalf("evaluated content type: %v", ct)
	}
	for name, h := range map[string]map[string]string{
		"gzip":                {"Content-Encoding": "gzip"},
		"method override":     {"X-HTTP-Method-Override": "DELETE"},
		"underscore override": {"X_Method_Override": "DELETE"},
	} {
		for k, v := range agent {
			h[k] = v
		}
		if resp, _ := send(t, s.URL+"/v1/refunds", `{}`, h); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	// A chunked request declaring a trailer.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+"/v1/refunds", io.NopCloser(strings.NewReader(`{}`)))
	for k, v := range agent {
		req.Header.Set(k, v)
	}
	req.TransferEncoding = []string{"chunked"}
	req.Trailer = http.Header{"X-Late": {"1"}}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("trailer: %d", resp.StatusCode)
	}
	if len(p.got) != 1 || len(u.reqs) != 1 {
		t.Fatalf("asked %d, forwarded %d", len(p.got), len(u.reqs))
	}
}

// TestPEPRefusesWithoutAUsableAnswer: a redirect from the decision
// endpoint, an answer without a decision and a token that cannot be had
// all answer 503 and forward nothing; a decision without an action token
// forwards no PAP-Action (D101 L7).
func TestPEPRefusesWithoutAUsableAnswer(t *testing.T) {
	for name, decide := range map[string]func(map[string]any) (int, string){
		"no decision": func(map[string]any) (int, string) { return http.StatusOK, `{"context":{}}` },
		"a redirect":  func(map[string]any) (int, string) { return http.StatusFound, `` },
	} {
		_, u, s := setup(t, "http", decide)
		if resp, _ := send(t, s.URL+"/x", `{}`, agent); resp.StatusCode != http.StatusServiceUnavailable || len(u.reqs) != 0 {
			t.Errorf("%s: %d, %d forwarded", name, resp.StatusCode, len(u.reqs))
		}
	}
	ps := httptest.NewServer(&pdp{decide: allow})
	t.Cleanup(ps.Close)
	us := httptest.NewServer(&upstream{})
	t.Cleanup(us.Close)
	h, err := pep.New(pep.Config{Server: ps.URL, Connection: "payments", PublicURL: "https://p.example.test", Upstream: us.URL, Tokens: failingToken{}})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	if resp, _ := send(t, s.URL+"/x", `{}`, agent); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}

type failingToken struct{}

func (failingToken) Token(context.Context) (string, error) { return "", pep.ErrToken }

// refreshing hands out a new token after each Invalidate.
type refreshing struct{ n atomic.Int32 }

func (r *refreshing) Token(context.Context) (string, error) {
	return "tok" + strconv.Itoa(int(r.n.Load())), nil
}
func (r *refreshing) Invalidate() { r.n.Add(1) }

// TestPEPDropsARefusedToken: a 401 drops the token and asks once more
// with a new one (D101 L4); the target's own PAP/PC headers never reach
// the agent (L5).
func TestPEPDropsARefusedToken(t *testing.T) {
	p := &pdp{}
	p.decide = func(map[string]any) (int, string) {
		if p.bearer[len(p.bearer)-1] == "Bearer tok0" {
			return http.StatusUnauthorized, ``
		}
		return http.StatusOK, `{"decision":true,"context":{"pantherclaw":{"outcome":"allow","transaction_id":"tx1","coverage":"PARTIAL"}}}`
	}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	us := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("PC-Outcome", "forged")
		w.Header().Set("PC-Transaction-Id", "forged")
		w.Header().Set("PAP-Nonce", "forged")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(us.Close)
	tok := &refreshing{}
	h, err := pep.New(pep.Config{Server: ps.URL, Connection: "payments", PublicURL: "https://p.example.test", Upstream: us.URL, Tokens: tok})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	resp, _ := send(t, s.URL+"/x", `{}`, agent)
	if resp.StatusCode != http.StatusOK || len(p.bearer) != 2 || p.bearer[1] != "Bearer tok1" {
		t.Fatalf("retry: %d %v", resp.StatusCode, p.bearer)
	}
	if v := resp.Header.Values("PC-Outcome"); len(v) != 1 || v[0] != "allow" || resp.Header.Get("PC-Transaction-Id") != "tx1" || resp.Header.Get("PAP-Nonce") != "" {
		t.Fatalf("headers: %v", resp.Header)
	}
}

// TestPEPConfiguration: an upstream with a query, an http server that is
// not loopback, and a forwarded PAP or PC header are refused (D101 L1, L2).
func TestPEPConfiguration(t *testing.T) {
	base := pep.Config{Server: "http://127.0.0.1:1", Connection: "c", PublicURL: "https://p.example.test", Upstream: "http://127.0.0.1:2", Tokens: staticToken("t")}
	for name, mutate := range map[string]func(*pep.Config){
		"an upstream query": func(c *pep.Config) { c.Upstream = "http://127.0.0.1:2/?a=1" },
		"plain http server": func(c *pep.Config) { c.Server = "http://pc.example.test" },
		"forwarding PAP":    func(c *pep.Config) { c.ForwardHeaders = []string{"PAP-Action"} },
		"forwarding PC_":    func(c *pep.Config) { c.ForwardHeaders = []string{"pc_action_id"} },
		"forwarding auth":   func(c *pep.Config) { c.ForwardHeaders = []string{"Authorization"} },
	} {
		c := base
		mutate(&c)
		if _, err := pep.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := base
	c.Server, c.AllowInsecure = "http://pc.example.test", true
	if _, err := pep.New(c); err != nil {
		t.Fatalf("insecure allowed: %v", err)
	}
}
