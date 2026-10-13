// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package githubhttp asks GitHub which account a sign-in's user access
// token belongs to (G0 M8 P2f, HR-207). The sign-in App checks the token
// with its client secret (POST /applications/{client_id}/token), and GitHub
// names its account only if that App issued it: a personal access token,
// a gh token or another App's is no proof. The token is then revoked
// (DELETE), so it is used for this one check and works nowhere after.
package githubhttp

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// loginRe is what GitHub logins look like (the github_identities check).
var loginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

// Verifier implements app.Verifier against GitHub's REST API.
type Verifier struct {
	// APIURL is GitHub's API URL (https://api.github.com, a GitHub
	// Enterprise Server's https://host/api/v3, or the simulator).
	APIURL string
	// ClientID and ClientSecret are the sign-in App's: a GitHub App with no
	// permissions, installed nowhere, whose device flow people sign in
	// through.
	ClientID     string
	ClientSecret pclog.Secret[[]byte]
	// Client sends the requests; nil uses a 10-second control-plane client
	// (no redirects, no proxy variables: GitHub is a configured URL).
	Client *http.Client
}

// User implements app.Verifier: a person's account (not a bot or an
// organization) that GitHub says the token, issued by the sign-in App,
// belongs to. The token is revoked before User returns the account.
// GitHub not knowing the token as the sign-in App's is app.ErrProof;
// GitHub not answering, refusing the App's secret or failing to revoke the
// token is app.ErrGitHubUnavailable, never a proof.
func (v *Verifier) User(ctx context.Context, token string) (app.GitHubUser, error) {
	if token == "" || strings.ContainsAny(token, " \r\n\t\"\\") {
		return app.GitHubUser{}, app.ErrProof
	}
	status, body, err := v.call(ctx, http.MethodPost, token)
	switch {
	case err != nil:
		return app.GitHubUser{}, err
	case status == http.StatusNotFound || status == http.StatusUnprocessableEntity:
		return app.GitHubUser{}, app.ErrProof
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return app.GitHubUser{}, fmt.Errorf("%w: GitHub refused the sign-in App's client id or secret (HTTP %d)", app.ErrGitHubUnavailable, status)
	case status != http.StatusOK:
		return app.GitHubUser{}, fmt.Errorf("%w: checking the token answered HTTP %d", app.ErrGitHubUnavailable, status)
	}
	var t struct {
		App struct {
			ClientID string `json:"client_id"`
		} `json:"app"`
		User struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
			Type  string `json:"type"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &t); err != nil || t.App.ClientID != v.ClientID {
		return app.GitHubUser{}, app.ErrProof
	}
	// The token is the sign-in App's: it is revoked whatever its account.
	if err := v.revoke(ctx, token); err != nil {
		return app.GitHubUser{}, err
	}
	u := t.User
	if u.ID <= 0 || !loginRe.MatchString(u.Login) || u.Type != "User" {
		return app.GitHubUser{}, app.ErrProof
	}
	return app.GitHubUser{ID: u.ID, Login: u.Login}, nil
}

// revoke makes the sign-in App's token stop working; one already revoked
// is fine.
func (v *Verifier) revoke(ctx context.Context, token string) error {
	switch status, _, err := v.call(ctx, http.MethodDelete, token); {
	case err != nil:
		return err
	case status != http.StatusNoContent && status != http.StatusNotFound:
		return fmt.Errorf("%w: revoking the sign-in token answered HTTP %d", app.ErrGitHubUnavailable, status)
	}
	return nil
}

// call sends {"access_token": token} to /applications/{client_id}/token as
// the sign-in App, and reads GitHub's answer.
func (v *Verifier) call(ctx context.Context, method, token string) (int, []byte, error) {
	in, err := json.Marshal(map[string]string{"access_token": token})
	if err != nil {
		return 0, nil, err
	}
	target := strings.TrimSuffix(v.APIURL, "/") + "/applications/" + url.PathEscape(v.ClientID) + "/token"
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(in))
	if err != nil {
		return 0, nil, err
	}
	var secret string
	if v.ClientSecret.IsSet() {
		secret = string(v.ClientSecret.Reveal())
	}
	req.SetBasicAuth(v.ClientID, secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	c := v.Client
	if c == nil {
		c = httpx.NewControlClient(httpx.ControlConfig{Timeout: 10 * time.Second})
	}
	res, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", app.ErrGitHubUnavailable, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", app.ErrGitHubUnavailable, err)
	}
	return res.StatusCode, body, nil
}
