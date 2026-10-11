// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// App JWT lifetime (HR-204): issued a minute in the past for clock skew,
// as GitHub recommends, and expiring nine minutes ahead, inside GitHub's
// ten-minute limit.
const (
	jwtBackdate = 60 * time.Second
	jwtLifetime = 9 * time.Minute
	// maxToken bounds an opaque token: GitHub may change its format, and
	// egress headers allow 4 KiB (ADR-0021 item 4).
	maxToken = 4 << 10
)

// Errors of a per-action installation token. Each fails the dispatch
// before the action's request is sent (enforcement_failed).
var (
	ErrScope   = errors.New("broker: the operation declares no GitHub App permissions, or its target names no repository")
	ErrAccount = errors.New("broker: the target repository is not on the account the App is installed on")
	ErrMint    = errors.New("broker: GitHub did not mint an installation token")
	// ErrScopeMismatch reports a token GitHub granted for more than was
	// asked: it is revoked and nothing is dispatched (ADR-0021 item 3).
	ErrScopeMismatch = errors.New("broker: GitHub granted a wider token than requested")
)

// Sender sends requests to the connection's host only: the connection's
// egress client (HR-070..074).
type Sender interface {
	HTTPRequest(ctx context.Context, r egress.Request) (*http.Request, error)
	Do(req *http.Request) (egress.Response, error)
}

// Installation is a minted installation token. Use places it; Revoke ends
// it at GitHub and clears it. It lives for one action and is never cached
// or returned to the agent (HR-203).
type Installation struct {
	token []byte
	base  *url.URL
	hosts []string
}

// Token is the token's bytes, which a caller scrubs from what goes back to
// the agent; they are cleared by Revoke.
func (t *Installation) Token() []byte { return t.token }

// MintInstallationToken signs an App JWT with the opened credential's key
// and asks GitHub, through the connection's own client and hosts, for an
// installation token for exactly owner/repo and the operation's declared
// permissions (HR-203, HR-204). GitHub's answer must name exactly that
// repository and those permissions; anything else is revoked and refused.
func MintInstallationToken(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp,
	owner, repo string, permissions map[string]string, now time.Time,
) (*Installation, error) {
	if len(permissions) == 0 || owner == "" || repo == "" {
		return nil, ErrScope
	}
	if owner != app.Account {
		return nil, ErrAccount
	}
	key, err := app.Key()
	if err != nil {
		return nil, err
	}
	jwt, err := appJWT(key, app.Issuer, now)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMint, err)
	}
	body, err := json.Marshal(map[string]any{"repositories": []string{repo}, "permissions": permissions}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	res, err := send(ctx, s, base, hosts, http.MethodPost, "/app/installations/"+strconv.FormatInt(app.Installation, 10)+"/access_tokens", body, jwt)
	clear(jwt)
	if err != nil {
		return nil, err
	}
	var out struct {
		Token        string            `json:"token"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if res.Status != http.StatusCreated || json.Unmarshal(res.Body, &out) != nil || !opaque(out.Token) {
		clear(res.Body)
		return nil, fmt.Errorf("%w: status %d", ErrMint, res.Status)
	}
	clear(res.Body)
	t := &Installation{token: []byte(out.Token), base: base, hosts: hosts}
	granted := make([]string, len(out.Repositories))
	for i, r := range out.Repositories {
		granted[i] = strings.ToLower(r.FullName)
	}
	if !slices.Equal(granted, []string{owner + "/" + repo}) || !maps.Equal(out.Permissions, permissions) {
		_ = t.Revoke(ctx, s) // refused either way; an unrevoked token expires within the hour
		return nil, ErrScopeMismatch
	}
	return t, nil
}

// opaque accepts a token as GitHub documents it, opaque: it is not parsed,
// only kept to what a header can carry (printable ASCII without spaces, at
// most 4 KiB; stateless tokens are about 520 bytes).
func opaque(t string) bool {
	return t != "" && len(t) <= maxToken && !strings.ContainsFunc(t, func(r rune) bool { return r <= ' ' || r > '~' })
}

// Place sets "Authorization: Bearer <token>" on req, for the credential's
// hosts only, with the pinned GitHub API version (ADR-0021 item 7).
func (t *Installation) Place(req *http.Request) error {
	apiHeaders(req)
	return Place(req, t.hosts, domain.GitHubAppHeader, domain.GitHubAppScheme, t.token)
}

// apiHeaders pins the GitHub REST API version and media type.
func apiHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// Revoke ends the token at GitHub (DELETE /installation/token), trying a
// second time when the first fails, and clears it. A token that could not
// be revoked expires within the hour GitHub set; the caller reports it
// (ADR-0021 item 6).
func (t *Installation) Revoke(ctx context.Context, s Sender) error {
	defer clear(t.token)
	var err error
	for range 2 {
		var res egress.Response
		if res, err = send(ctx, s, t.base, t.hosts, http.MethodDelete, "/installation/token", nil, t.token); err == nil && res.Status == http.StatusNoContent {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("broker: revoking the installation token answered %d", res.Status)
		}
	}
	return err
}

// send makes one GitHub API call under base with a bearer credential.
func send(ctx context.Context, s Sender, base *url.URL, hosts []string, method, path string, body, bearer []byte) (egress.Response, error) {
	u := *base
	u.Path = strings.TrimSuffix(base.Path, "/") + path
	req, err := s.HTTPRequest(ctx, egress.Request{Method: method, URL: &u, Body: body})
	if err != nil {
		return egress.Response{}, err
	}
	apiHeaders(req)
	if err := Place(req, hosts, domain.GitHubAppHeader, domain.GitHubAppScheme, bearer); err != nil {
		return egress.Response{}, err
	}
	return s.Do(req)
}

// appJWT signs an App JWT (RS256): issued a minute ago, expiring within
// ten minutes (HR-204). The caller clears it.
func appJWT(key *rsa.PrivateKey, issuer string, now time.Time) ([]byte, error) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iss": issuer, "iat": now.Add(-jwtBackdate).Unix(), "exp": now.Add(jwtLifetime).Unix(),
	}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	signing := head + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, err
	}
	return []byte(signing + "." + base64.RawURLEncoding.EncodeToString(sig)), nil
}
