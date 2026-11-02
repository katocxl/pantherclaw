// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package okta_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/idjag"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/sim/okta"
)

func start(t *testing.T) (*okta.Sim, *httptest.Server) {
	t.Helper()
	var h http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	sim, err := okta.New(srv.URL, okta.Faults{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h = sim.Handler()
	return sim, srv
}

func post(t *testing.T, u string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.Post(u, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.UnmarshalRead(resp.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSimOktaIssuesDraft06Assertions: the simulator's token exchange gives
// an ID-JAG that the draft -06 verifier accepts, and each fault makes it
// refuse (SIMULATED).
//
// Covers: F910
func TestSimOktaIssuesDraft06Assertions(t *testing.T) {
	sim, srv := start(t)
	const aud = "https://pc.example.com/orgs/0190d0c4-0000-7000-8000-000000000001"
	signIn := post(t, srv.URL+"/__sim/sign-in", url.Values{"sub": {"00u1"}, "client_id": {"agent-client"}})
	idTok, _ := signIn["id_token"].(string)
	exchange := func() string {
		out := post(t, srv.URL+"/oauth2/v1/token", url.Values{
			"grant_type": {okta.GrantTokenExchange}, "requested_token_type": {okta.TypeIDJAG}, "audience": {aud},
			"resource": {"https://gw.example.com/mcp-oauth/github"}, "scope": {"tickets.read"}, "subject_token": {idTok},
			"subject_token_type": {okta.TypeIDToken}, "client_id": {"agent-client"},
		})
		if out["issued_token_type"] != okta.TypeIDJAG || out["token_type"] != "N_A" {
			t.Fatalf("exchange: %v", out)
		}
		s, _ := out["access_token"].(string)
		return s
	}
	v := &idjag.Verifier{Client: srv.Client(), CheckURL: func(string) error { return nil }}
	iss := domain.Issuer{URL: sim.Issuer(), Audience: aud, Algorithms: []string{"RS256"}}
	a, err := v.Verify(context.Background(), exchange(), iss, time.Now())
	if err != nil || a.Subject != "00u1" || a.ClientID != "agent-client" || a.Scope != "tickets.read" {
		t.Fatalf("verify: %+v %v", a, err)
	}
	for _, f := range []okta.Faults{{Expired: true}, {WrongAudience: true}, {Cnf: true}} {
		sim.SetFaults(f)
		if _, err := v.Verify(context.Background(), exchange(), iss, time.Now()); !errors.Is(err, domain.ErrAssertion) {
			t.Errorf("%+v: %v", f, err)
		}
	}
	if sim.Issued() != 4 {
		t.Fatalf("issued %d", sim.Issued())
	}
	if out := post(t, srv.URL+"/oauth2/v1/token", url.Values{"grant_type": {okta.GrantTokenExchange}}); out["error"] != "invalid_request" {
		t.Fatalf("a malformed exchange: %v", out)
	}
}
