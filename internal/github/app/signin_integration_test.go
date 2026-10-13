// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/github/adapters/githubhttp"
	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/github/deviceflow"
	"github.com/katocxl/pantherclaw/internal/platform/log"
	simgithub "github.com/katocxl/pantherclaw/internal/sim/github"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func noWait(context.Context, time.Duration) error { return nil }

// TestHR207_ADeviceFlowSignInProvesTheAccount (P2f): against the GitHub
// simulator, a person runs the GitHub App's device flow, signs in at GitHub
// as their account, and the server links that account, the one GitHub says
// the token belongs to, with the time it was proved. A token GitHub never
// issued, a sign-in refused at GitHub, another App's client id and a
// server without GitHub sign-in link nothing.
func TestHR207_ADeviceFlowSignInProvesTheAccount(t *testing.T) {
	e := newEnv(t)
	sim := simgithub.New(log.Discard())
	sim.RegisterApp(1, "Iv1.pantherclaw", nil)
	gh := httptest.NewServer(sim.Handler())
	t.Cleanup(gh.Close)
	e.svc.Verifier = &githubhttp.Verifier{APIURL: gh.URL}
	e.svc.SignIn = app.SignIn{ClientID: "Iv1.pantherclaw", WebURL: gh.URL}
	alice := e.person(t, "alice")
	asAlice := e.as(alice, td.KindUser, td.RoleCodeReviewer)
	ctx := context.Background()

	cfg, err := e.svc.SignInConfig(asAlice)
	if err != nil || cfg.ClientID != "Iv1.pantherclaw" || cfg.WebURL != gh.URL {
		t.Fatalf("sign-in %+v %v", cfg, err)
	}
	flow := &deviceflow.Flow{WebURL: cfg.WebURL, ClientID: cfg.ClientID, Wait: noWait}
	signIn := func(decide func(code string) error) (string, error) {
		return flow.Token(ctx, func(c deviceflow.Code) {
			if err := decide(c.UserCode); err != nil {
				t.Error(err)
			}
		})
	}
	token, err := signIn(func(code string) error {
		return sim.AuthorizeDevice(code, simgithub.DeviceUser{ID: 4242, Login: "alice-gh"})
	})
	if err != nil {
		t.Fatal(err)
	}
	link, err := e.svc.Prove(asAlice, token, false)
	if err != nil || link.UserID != alice || link.GithubUserID != 4242 || link.GithubLogin != "alice-gh" || link.VerifiedAt == nil {
		t.Fatalf("link %+v %v", link, err)
	}

	if _, err := e.svc.Prove(asAlice, "ghu_never_issued", false); !errors.Is(err, app.ErrProof) {
		t.Fatalf("a token GitHub never issued: %v", err)
	}
	if _, err := signIn(sim.DenyDevice); !errors.Is(err, deviceflow.ErrDenied) {
		t.Fatalf("a sign-in refused at GitHub: %v", err)
	}
	if _, err := (&deviceflow.Flow{WebURL: gh.URL, ClientID: "Iv1.another", Wait: noWait}).Token(ctx, func(deviceflow.Code) {}); err == nil {
		t.Fatal("another App's client id got a device code")
	}
	if _, err := (&app.Service{Pool: e.pool}).SignInConfig(asAlice); !errors.Is(err, app.ErrNoSignIn) {
		t.Fatalf("a server without GitHub sign-in: %v", err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.github_identities WHERE verified_at IS NOT NULL"); n != 1 {
		t.Fatalf("%d proved links, want alice's", n)
	}
}
