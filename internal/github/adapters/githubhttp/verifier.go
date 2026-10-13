// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package githubhttp asks GitHub which account a sign-in's user access
// token belongs to (G0 M8 P2f, HR-207): GET /user with the token is the
// proof that whoever sent it signed in to GitHub as that account. The token
// is used for that one request and kept nowhere.
package githubhttp

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// loginRe is what GitHub logins look like (the github_identities check).
var loginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)

// Verifier implements app.Verifier against GitHub's REST API.
type Verifier struct {
	// APIURL is GitHub's API origin (https://api.github.com, or the
	// simulator).
	APIURL string
	// Client sends the request; nil uses a 10-second control-plane client
	// (no redirects, no proxy variables: GitHub is a configured URL).
	Client *http.Client
}

// User implements app.Verifier: a person's account (not a bot or an
// organization) that GitHub says the token belongs to. GitHub refusing the
// token is app.ErrProof; GitHub not answering is app.ErrGitHubUnavailable.
func (v *Verifier) User(ctx context.Context, token string) (app.GitHubUser, error) {
	if token == "" || strings.ContainsAny(token, " \r\n\t") {
		return app.GitHubUser{}, app.ErrProof
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(v.APIURL, "/")+"/user", nil)
	if err != nil {
		return app.GitHubUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	c := v.Client
	if c == nil {
		c = httpx.NewControlClient(httpx.ControlConfig{Timeout: 10 * time.Second})
	}
	res, err := c.Do(req)
	if err != nil {
		return app.GitHubUser{}, fmt.Errorf("%w: %w", app.ErrGitHubUnavailable, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 256<<10))
	switch {
	case err != nil:
		return app.GitHubUser{}, fmt.Errorf("%w: %w", app.ErrGitHubUnavailable, err)
	case res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden:
		return app.GitHubUser{}, app.ErrProof
	case res.StatusCode != http.StatusOK:
		return app.GitHubUser{}, fmt.Errorf("%w: GET /user answered HTTP %d", app.ErrGitHubUnavailable, res.StatusCode)
	}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Type  string `json:"type"`
	}
	if err := json.Unmarshal(body, &u); err != nil || u.ID <= 0 || !loginRe.MatchString(u.Login) || u.Type != "User" {
		return app.GitHubUser{}, app.ErrProof
	}
	return app.GitHubUser{ID: u.ID, Login: u.Login}, nil
}
