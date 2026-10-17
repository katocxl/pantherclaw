// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func TestAuthZENParse(t *testing.T) {
	one := `{"subject":{"type":"pantherclaw_workload","id":"a"},"resource":{"type":"pantherclaw:http_request","id":"payments"},"action":{"name":"POST"}}`
	evs, sem, err := parseAuthZEN([]byte(one), false)
	if err != nil || len(evs) != 1 || sem != semanticExecuteAll || evs[0].Resource.ID != "payments" {
		t.Fatalf("one: %+v %q %v", evs, sem, err)
	}
	if _, _, err := parseAuthZEN([]byte(`{"evaluations":[{}]}`), false); err == nil {
		t.Fatal("evaluations on the single endpoint")
	}
	batch := `{"subject":{"type":"pantherclaw_workload"},"action":{"name":"POST"},
	  "evaluations":[{"resource":{"type":"pantherclaw:http_request","id":"a"}},{"resource":{"type":"pantherclaw:http_request","id":"b"},"action":{"name":"GET"}}],
	  "options":{"evaluations_semantic":"deny_on_first_deny"}}`
	evs, sem, err = parseAuthZEN([]byte(batch), true)
	if err != nil || len(evs) != 2 || sem != semanticDenyOnFirstDeny || evs[0].Action.Name != "POST" || evs[1].Action.Name != "GET" ||
		evs[1].Subject == nil {
		t.Fatalf("batch defaults: %+v %q %v", evs, sem, err)
	}
	if _, _, err := parseAuthZEN([]byte(`{"options":{"evaluations_semantic":"maybe"}}`), true); err == nil {
		t.Fatal("unknown semantic")
	}
	many := `{"evaluations":[` + strings.Repeat(`{},`, authzenMaxBatch) + `{}]}`
	if _, _, err := parseAuthZEN([]byte(many), true); err == nil {
		t.Fatal("a batch of 11")
	}
	if _, _, err := parseAuthZEN([]byte(`not json`), true); err == nil {
		t.Fatal("not JSON")
	}
}

func TestAuthZENWithinBase(t *testing.T) {
	base := "https://pay.example.test:8443/api"
	for raw, want := range map[string]string{
		"https://pay.example.test:8443/api/v1/refunds?x=1": "/v1/refunds",
		"https://PAY.example.test:8443/api":                "/",
		"https://pay.example.test:8443/apix/v1":            "",
		"https://pay.example.test/api/v1":                  "",
		"http://pay.example.test:8443/api/v1":              "",
		"https://other.test:8443/api/v1":                   "",
		"https://u:p@pay.example.test:8443/api/v1":         "",
		"https://pay.example.test:8443/api/v1#f":           "",
		"/api/v1":                                          "",
	} {
		_, rest, ok := withinBase(&base, raw)
		if (want != "") != ok || rest != want {
			t.Errorf("%s: %q %v, want %q", raw, rest, ok, want)
		}
	}
	if _, _, ok := withinBase(nil, "https://pay.example.test:8443/api"); ok {
		t.Fatal("a connection without a base URL")
	}
}

func TestAuthZENJSONRPC(t *testing.T) {
	tc, m, err := jsonRPC([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund","arguments":{"a":1}}}`))
	if err != nil || m != "tools/call" || tc.Name != "create_refund" || string(tc.Arguments) != `{"a":1}` {
		t.Fatalf("tools/call: %+v %q %v", tc, m, err)
	}
	if _, m, err := jsonRPC([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); err != nil || m != "tools/list" {
		t.Fatalf("tools/list: %q %v", m, err)
	}
	for _, bad := range []string{`[{"jsonrpc":"2.0","method":"ping"}]`, `{"method":"ping"}`, `{"jsonrpc":"2.0","method":"tools/call","params":{}}`} {
		if _, _, err := jsonRPC([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

func TestAuthZENPointRates(t *testing.T) {
	clk := clock.NewFake(time.Now())
	l := newPointRates(clk)
	a, b := ids.NewV7(), ids.NewV7()
	if !l.allow(a, 3, 2) || !l.allow(a, 3, 1) || l.allow(a, 3, 1) {
		t.Fatal("a point's rate")
	}
	if !l.allow(b, 3, 3) {
		t.Fatal("another point has its own rate")
	}
	clk.Advance(time.Second)
	if !l.allow(a, 3, 3) {
		t.Fatal("a new second")
	}
}

func TestAuthZENWorkloadSubject(t *testing.T) {
	org, agent, inst := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	claims, _ := json.Marshal(map[string]any{"sub": "pc:org/" + org.String() + "/agent/" + agent.String() + "/inst/" + inst.String(), "pap": map[string]string{"env": "e"}})
	tok := "x." + base64.RawURLEncoding.EncodeToString(claims) + ".y"
	i, env, a, ok := workloadSubject(tok)
	if !ok || i != inst.String() || env != "e" || a != agent.String() {
		t.Fatalf("subject: %v %q %q %q", ok, i, env, a)
	}
	if _, _, _, ok := workloadSubject("x.e30.y"); ok {
		t.Fatal("a token naming nobody")
	}
}

// fakeAuthn authenticates one bearer as the caller.
type fakeAuthn struct {
	bearer string
	caller tapp.Caller
}

func (f fakeAuthn) Authenticate(_ context.Context, bearer string) (tapp.Caller, error) {
	if bearer != f.bearer {
		return tapp.Caller{}, authnapp.ErrUnauthenticated
	}
	return f.caller, nil
}

// TestAuthZENRefusesCallersThatAreNotEnforcementPoints: no bearer, a bad
// one, a person, an API key and a service account without
// authzen.evaluate all get 401 with WWW-Authenticate, before any body is
// read (D26). The metadata needs no credential.
func TestAuthZENRefusesCallersThatAreNotEnforcementPoints(t *testing.T) {
	org := ids.New[ids.Org]()
	sa := td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}
	evaluator := []td.Binding{{Role: td.RoleEnforcementPoint, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}}
	for name, c := range map[string]tapp.Caller{
		"a person":          {Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: evaluator}, Credential: tapp.CredAccessToken},
		"an API key":        {Subject: td.Subject{Org: org, Principal: sa, Bindings: evaluator}, Credential: tapp.CredAPIKey},
		"without the role":  {Subject: td.Subject{Org: org, Principal: sa}, Credential: tapp.CredAccessToken},
		"a browser session": {Subject: td.Subject{Org: org, Principal: sa, Bindings: evaluator}, Credential: tapp.CredBrowserSession},
	} {
		e := newAuthZENEndpoint(nil, fakeAuthn{bearer: "good", caller: c}, nil, "https://pc.example.test", celenv.Limits{}, nil, nil)
		mux := http.NewServeMux()
		e.mount(mux)
		for _, auth := range []string{"", "Bearer bad", "Bearer good"} {
			req := httptest.NewRequest(http.MethodPost, authzenEvaluationPath, strings.NewReader(`{}`))
			req.Header.Set("X-Request-ID", "r-1")
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Bearer") ||
				w.Header().Get("X-Request-ID") != "r-1" {
				t.Errorf("%s with %q: %d %v", name, auth, w.Code, w.Header())
			}
		}
	}
	e := newAuthZENEndpoint(nil, fakeAuthn{}, nil, "https://pc.example.test/", celenv.Limits{}, nil, nil)
	mux := http.NewServeMux()
	e.mount(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authzenConfigPath, nil))
	var md authzenMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil || w.Code != http.StatusOK ||
		md.PolicyDecisionPoint != "https://pc.example.test" || md.AccessEvaluationEndpoint != "https://pc.example.test/access/v1/evaluation" ||
		md.AccessEvaluationsEndpoint != "https://pc.example.test/access/v1/evaluations" || len(md.Capabilities) != 1 ||
		md.Capabilities[0] != AuthZENCapability {
		t.Fatalf("metadata: %d %s", w.Code, w.Body)
	}
}
