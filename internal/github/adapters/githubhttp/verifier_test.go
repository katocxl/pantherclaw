// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubhttp_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/github/adapters/githubhttp"
	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/github/deviceflow"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	simgithub "github.com/katocxl/pantherclaw/internal/sim/github"
)

// TestHR207_OnlyGitHubsAnswerForAPersonsTokenProvesAnAccount (P2f, review
// 2026-10-13): a token proves an account only when GitHub, asked by the
// sign-in App with its secret, says that App issued it to a person's
// account; the token is then revoked. A personal access token or another
// App's token, a bot or organization, an answer for another App or one
// that is not an account is no proof, and a token the sign-in App issued is
// revoked whatever its account. GitHub failing to answer, refusing the
// App's secret or failing to revoke is unavailable, never a proof.
func TestHR207_OnlyGitHubsAnswerForAPersonsTokenProvesAnAccount(t *testing.T) {
	sim := simgithub.New(pclog.Discard())
	sim.RegisterSignInApp("Iv1.signin", "s3cret")
	sim.SignInAs(simgithub.DeviceUser{ID: 7, Login: "alice-gh"})
	gh := httptest.NewServer(sim.Handler())
	t.Cleanup(gh.Close)
	ctx := context.Background()
	flow := &deviceflow.Flow{WebURL: gh.URL, ClientID: "Iv1.signin", Wait: func(context.Context, time.Duration) error { return nil }}
	token, err := flow.Token(ctx, func(deviceflow.Code) {})
	if err != nil {
		t.Fatal(err)
	}
	v := &githubhttp.Verifier{APIURL: gh.URL + "/", ClientID: "Iv1.signin", ClientSecret: pclog.NewSecret([]byte("s3cret"))}
	if _, err := (&githubhttp.Verifier{APIURL: gh.URL, ClientID: "Iv1.signin", ClientSecret: pclog.NewSecret([]byte("guess"))}).User(ctx, token); !errors.Is(err, app.ErrGitHubUnavailable) ||
		errors.Is(err, app.ErrProof) {
		t.Fatalf("a wrong client secret: %v", err)
	}
	if u, err := v.User(ctx, token); err != nil || u.ID != 7 || u.Login != "alice-gh" {
		t.Fatalf("the sign-in App's token: %+v %v", u, err)
	}
	if !sim.Revoked(token) {
		t.Fatal("the token still works after the check")
	}
	for _, tok := range []string{token, "ghp_personal", "gho_cli", "", "two words", `x"y`} {
		if _, err := v.User(ctx, tok); !errors.Is(err, app.ErrProof) {
			t.Errorf("%q: %v", tok, err)
		}
	}

	answers := map[string]struct {
		check, revoke int
		body          string
	}{
		"bot":     {http.StatusOK, http.StatusNoContent, `{"app": {"client_id": "Iv1.signin"}, "user": {"id": 8, "login": "ci-bot", "type": "Bot"}}`},
		"org":     {http.StatusOK, http.StatusNoContent, `{"app": {"client_id": "Iv1.signin"}, "user": {"id": 9, "login": "acme", "type": "Organization"}}`},
		"junk":    {http.StatusOK, http.StatusNoContent, `{"app": {"client_id": "Iv1.signin"}, "user": {"id": -1, "login": "-x-", "type": "User"}}`},
		"other":   {http.StatusOK, http.StatusNoContent, `{"app": {"client_id": "Iv1.merges"}, "user": {"id": 7, "login": "alice-gh", "type": "User"}}`},
		"down":    {http.StatusBadGateway, http.StatusNoContent, `oops`},
		"kept":    {http.StatusOK, http.StatusInternalServerError, `{"app": {"client_id": "Iv1.signin"}, "user": {"id": 7, "login": "alice-gh", "type": "User"}}`},
		"revoked": {http.StatusOK, http.StatusNotFound, `{"app": {"client_id": "Iv1.signin"}, "user": {"id": 7, "login": "alice-gh", "type": "User"}}`},
	}
	var revoked []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.UnmarshalRead(r.Body, &in)
		a, ok := answers[in.AccessToken]
		if r.URL.Path != "/applications/Iv1.signin/token" || !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			revoked = append(revoked, in.AccessToken)
			w.WriteHeader(a.revoke)
			return
		}
		w.WriteHeader(a.check)
		_, _ = io.WriteString(w, a.body)
	}))
	t.Cleanup(fake.Close)
	v.APIURL = fake.URL
	for _, tok := range []string{"bot", "org", "junk", "other"} {
		if _, err := v.User(ctx, tok); !errors.Is(err, app.ErrProof) {
			t.Errorf("%q: %v", tok, err)
		}
	}
	if !slices.Equal(revoked, []string{"bot", "org", "junk"}) {
		t.Errorf("revoked %v, want every token the sign-in App issued", revoked)
	}
	for _, tok := range []string{"down", "kept"} {
		if _, err := v.User(ctx, tok); !errors.Is(err, app.ErrGitHubUnavailable) || errors.Is(err, app.ErrProof) {
			t.Errorf("%q: %v", tok, err)
		}
	}
	if u, err := v.User(ctx, "revoked"); err != nil || u.ID != 7 {
		t.Errorf("a token revoked meanwhile: %+v %v", u, err)
	}
	if _, err := (&githubhttp.Verifier{APIURL: "http://127.0.0.1:1", ClientID: "Iv1.signin"}).User(ctx, "ok"); !errors.Is(err, app.ErrGitHubUnavailable) {
		t.Errorf("GitHub unreachable: %v", err)
	}
}
