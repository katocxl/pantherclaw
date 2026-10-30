// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
)

type teamsWorld struct {
	sim    *teams.Server
	srv    *httptest.Server
	client *egress.Client
	oc     domain.OAuthClient
	hosts  []string
}

func newTeams(t *testing.T) *teamsWorld {
	t.Helper()
	sim := teams.New([]teams.Channel{{ID: teams.TeamID, Name: "General", Installed: true}}, teams.Faults{}, slog.New(slog.DiscardHandler)).
		WithRequire(teams.Require{ClientID: teams.AppID, ClientSecret: "s3cret~value"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	c, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return &teamsWorld{
		sim: sim, srv: srv, client: c, hosts: []string{u.Host},
		oc: domain.OAuthClient{
			V: 1, TokenURL: srv.URL + "/botframework.com/oauth2/v2.0/token", ClientID: teams.AppID, Scope: teams.Scope,
			ClientSecret: []byte("s3cret~value"),
		},
	}
}

// TestHR524_ATokenIsMintedPerDispatchAndTheSecretIsNeverPlaced: each mint
// is a fresh token from the token endpoint; what is placed is "Bearer
// <token>", never the client secret; the token works at the Bot Connector
// and is cleared after use.
// Covers: HR-524
func TestHR524_ATokenIsMintedPerDispatchAndTheSecretIsNeverPlaced(t *testing.T) {
	w := newTeams(t)
	var seen []string
	for range 2 {
		tok, err := MintClientToken(t.Context(), w.client, w.hosts, w.oc)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+"/teams/v3/teams/"+url.PathEscape(teams.TeamID)+"/conversations", nil)
		if err := tok.Place(req); err != nil {
			t.Fatal(err)
		}
		auth := req.Header.Get("Authorization")
		if auth != "Bearer "+string(tok.Token()) || auth == "Bearer s3cret~value" {
			t.Fatalf("placed %q", auth)
		}
		res, err := w.client.Do(req)
		if err != nil || res.Status != http.StatusOK {
			t.Fatalf("bot connector: %d %v", res.Status, err)
		}
		seen = append(seen, string(tok.Token()))
		tok.Clear()
		for _, b := range tok.Token() {
			if b != 0 {
				t.Fatal("token not cleared")
			}
		}
	}
	if seen[0] == seen[1] || w.sim.Issued() != 2 {
		t.Fatalf("tokens %v, issued %d: want a fresh token per dispatch", seen, w.sim.Issued())
	}
}

// TestHR524_TheTokenEndpointMustBeBound: a token endpoint on a host the seal
// does not bind never receives the client secret, and a token is placed on
// bound hosts only.
// Covers: HR-524
func TestHR524_TheTokenEndpointMustBeBound(t *testing.T) {
	w := newTeams(t)
	if _, err := MintClientToken(t.Context(), w.client, []string{"login.microsoftonline.com"}, w.oc); !errors.Is(err, ErrNotBound) {
		t.Fatalf("unbound token endpoint: %v", err)
	}
	if w.sim.Calls()["token"] != 0 {
		t.Fatal("the secret reached an unbound host")
	}
	tok, err := MintClientToken(t.Context(), w.client, w.hosts, w.oc)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://evil.example/teams/v3/conversations", nil)
	if err := tok.Place(req); !errors.Is(err, ErrNotBound) || req.Header.Get("Authorization") != "" {
		t.Fatalf("placed on an unbound host: %v", err)
	}
}

// TestHR524_ARefusedOrMalformedAnswerMintsNothing: a refused client, a
// token type other than Bearer and an unusable token are refused.
// Covers: HR-524
func TestHR524_ARefusedOrMalformedAnswerMintsNothing(t *testing.T) {
	w := newTeams(t)
	w.sim.SetFaults(teams.Faults{InvalidClient: true})
	if _, err := MintClientToken(t.Context(), w.client, w.hosts, w.oc); !errors.Is(err, ErrClientToken) {
		t.Fatalf("invalid client: %v", err)
	}
	for _, body := range []string{
		`{"token_type":"MAC","expires_in":3600,"access_token":"abc"}`,
		`{"token_type":"Bearer","expires_in":0,"access_token":"abc"}`,
		`{"token_type":"Bearer","expires_in":3600,"access_token":"a b"}`,
		`{"token_type":"Bearer","expires_in":3600,"access_token":""}`,
		`not json`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			_, _ = rw.Write([]byte(body))
		}))
		c, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(srv.URL)
		oc := w.oc
		oc.TokenURL = srv.URL + "/token"
		if _, err := MintClientToken(t.Context(), c, []string{u.Host}, oc); !errors.Is(err, ErrClientToken) {
			t.Errorf("%s: %v", body, err)
		}
		srv.Close()
	}
	bad := w.oc
	bad.ClientSecret = nil
	if _, err := MintClientToken(t.Context(), w.client, w.hosts, bad); !errors.Is(err, domain.ErrOAuthClient) {
		t.Fatalf("invalid credential: %v", err)
	}
}

func TestClientCredentialsFormEscapesEveryValue(t *testing.T) {
	got := string(clientCredentialsForm(domain.OAuthClient{ClientID: "a b", ClientSecret: []byte("x&y=z~"), Scope: teams.Scope}))
	want := "grant_type=client_credentials&client_id=a%20b&client_secret=x%26y%3Dz~&scope=https%3A%2F%2Fapi.botframework.com%2F.default"
	if got != want {
		t.Fatalf("got %s", got)
	}
}
