// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubhttp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/katocxl/pantherclaw/internal/github/adapters/githubhttp"
	"github.com/katocxl/pantherclaw/internal/github/app"
)

// TestHR207_OnlyGitHubsAnswerForAPersonsTokenProvesAnAccount (P2f): the
// account a token belongs to is GitHub's 200 answer to GET /user with it,
// for a person's account with a GitHub login; GitHub refusing the token,
// a bot or organization, an answer that is not an account, or a token that
// could not be sent is no proof, and GitHub failing to answer is
// unavailable, never a proof.
func TestHR207_OnlyGitHubsAnswerForAPersonsTokenProvesAnAccount(t *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"Bearer ok":     {http.StatusOK, `{"id": 7, "login": "alice-gh", "type": "User", "name": "Alice"}`},
		"Bearer bot":    {http.StatusOK, `{"id": 8, "login": "ci-bot", "type": "Bot"}`},
		"Bearer org":    {http.StatusOK, `{"id": 9, "login": "acme", "type": "Organization"}`},
		"Bearer junk":   {http.StatusOK, `{"id": -1, "login": "-x-", "type": "User"}`},
		"Bearer revoke": {http.StatusUnauthorized, `{"message": "Bad credentials"}`},
		"Bearer down":   {http.StatusBadGateway, `oops`},
	}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := answers[r.Header.Get("Authorization")]
		if r.URL.Path != "/user" || r.Method != http.MethodGet || !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(a.status)
		_, _ = io.WriteString(w, a.body)
	}))
	t.Cleanup(gh.Close)
	v := &githubhttp.Verifier{APIURL: gh.URL + "/"}
	ctx := context.Background()
	if u, err := v.User(ctx, "ok"); err != nil || u.ID != 7 || u.Login != "alice-gh" {
		t.Fatalf("a person's token: %+v %v", u, err)
	}
	for _, tok := range []string{"bot", "org", "junk", "revoke", "", "two words"} {
		if _, err := v.User(ctx, tok); !errors.Is(err, app.ErrProof) {
			t.Errorf("%q: %v", tok, err)
		}
	}
	if _, err := v.User(ctx, "down"); !errors.Is(err, app.ErrGitHubUnavailable) || errors.Is(err, app.ErrProof) {
		t.Errorf("GitHub down: %v", err)
	}
	if _, err := (&githubhttp.Verifier{APIURL: "http://127.0.0.1:1"}).User(ctx, "ok"); !errors.Is(err, app.ErrGitHubUnavailable) {
		t.Errorf("GitHub unreachable: %v", err)
	}
}
