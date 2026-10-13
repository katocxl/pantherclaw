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
	// revokeTimeout bounds a revocation, which runs on its own deadline
	// whatever the dispatch's context: a dispatch that ran long, or whose
	// agent went away, still revokes (ADR-0021 item 6).
	revokeTimeout = 10 * time.Second
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

// ScopeMismatch is the error of a wider grant (errors.Is ErrScopeMismatch).
// It carries what GitHub granted and whether the token was revoked, for
// the execution receipt of the refused dispatch.
type ScopeMismatch struct{ Access Access }

func (e *ScopeMismatch) Error() string { return ErrScopeMismatch.Error() }

// Is makes errors.Is(err, ErrScopeMismatch) hold.
func (e *ScopeMismatch) Is(target error) bool { return target == ErrScopeMismatch }

// mismatch revokes a token GitHub granted too widely and returns the
// error that carries its access.
func (t *Installation) mismatch(ctx context.Context, s Sender) error {
	_ = t.Revoke(ctx, s) // the receipt says whether it was; it expires within the hour anyway
	return &ScopeMismatch{Access: t.access}
}

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
	token  []byte
	base   *url.URL
	hosts  []string
	access Access
}

// Access is what an installation token allowed, for the execution receipt
// (ADR-0021 item 5): never the token.
type Access struct {
	Installation       int64
	Repository         string
	RepositoryID       int64
	Requested, Granted map[string]string
	Expires            time.Time
	// Revocation is "revoked" or "revoke_failed" once Revoke ran; empty
	// before.
	Revocation string
}

// Access is what the token allowed, and whether it was revoked.
func (t *Installation) Access() Access { return t.access }

// Token is the token's bytes, which a caller scrubs from what goes back to
// the agent; they are cleared by Revoke.
func (t *Installation) Token() []byte { return t.token }

// MintInstallationToken signs an App JWT with the opened credential's key
// and asks GitHub, through the connection's own client and hosts, for an
// installation token for exactly owner/repo and the operation's declared
// permissions (HR-203, HR-204). GitHub's answer must name exactly that
// repository and those permissions, with metadata: read, which every
// installation token carries; anything else is revoked and refused.
func MintInstallationToken(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp,
	owner, repo string, permissions map[string]string, now time.Time,
) (*Installation, error) {
	if len(permissions) == 0 || owner == "" || repo == "" {
		return nil, ErrScope
	}
	if owner != app.Account {
		return nil, ErrAccount
	}
	t, granted, err := mint(ctx, s, baseURL, hosts, app, []string{repo}, permissions, now)
	if err != nil {
		return nil, err
	}
	t.access.Repository = owner + "/" + repo
	if !slices.Equal(granted, []string{owner + "/" + repo}) {
		return nil, t.mismatch(ctx, s)
	}
	return t, nil
}

// MintScanToken mints a read-only token for an organization scan (G0 M8,
// HR-209, ADR-0021 item 2): for the named repositories of the installation,
// or, with none named, all of them (to list them first). GitHub's grant must
// name exactly those permissions, and repositories of the installation's
// account only, exactly the named ones when named.
func MintScanToken(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp, repos []string,
	permissions map[string]string, now time.Time,
) (*Installation, error) {
	if len(permissions) == 0 {
		return nil, ErrScope
	}
	for _, p := range permissions {
		if p != "read" {
			return nil, ErrScope
		}
	}
	t, granted, err := mint(ctx, s, baseURL, hosts, app, repos, permissions, now)
	if err != nil {
		return nil, err
	}
	want := make([]string, len(repos))
	for i, r := range repos {
		want[i] = app.Account + "/" + strings.ToLower(r)
	}
	slices.Sort(want)
	slices.Sort(granted)
	foreign := slices.ContainsFunc(granted, func(g string) bool { return !strings.HasPrefix(g, app.Account+"/") })
	if foreign || (repos != nil && !slices.Equal(granted, want)) {
		return nil, t.mismatch(ctx, s)
	}
	return t, nil
}

// mint asks GitHub for an installation token for repos (names, all of the
// installation's when nil) and permissions, and returns it with the
// repositories GitHub granted (lowercase full names). A grant of other
// permissions is revoked and refused here.
func mint(ctx context.Context, s Sender, baseURL string, hosts []string, app domain.GitHubApp, repos []string,
	permissions map[string]string, now time.Time,
) (*Installation, []string, error) {
	key, err := app.Key()
	if err != nil {
		return nil, nil, err
	}
	jwt, err := appJWT(key, app.Issuer, now)
	if err != nil {
		return nil, nil, err
	}
	base, err := url.Parse(strings.TrimSuffix(baseURL, "/"))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrMint, err)
	}
	asked := map[string]any{"permissions": permissions}
	if repos != nil {
		asked["repositories"] = repos
	}
	body, err := json.Marshal(asked, json.Deterministic(true))
	if err != nil {
		return nil, nil, err
	}
	res, err := send(ctx, s, base, hosts, http.MethodPost, "/app/installations/"+strconv.FormatInt(app.Installation, 10)+"/access_tokens", body, jwt)
	clear(jwt)
	if err != nil {
		return nil, nil, err
	}
	var out struct {
		Token        string            `json:"token"`
		Permissions  map[string]string `json:"permissions"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Repositories []struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if res.Status != http.StatusCreated || json.Unmarshal(res.Body, &out) != nil || !opaque(out.Token) {
		clear(res.Body)
		return nil, nil, fmt.Errorf("%w: status %d", ErrMint, res.Status)
	}
	clear(res.Body)
	t := &Installation{token: []byte(out.Token), base: base, hosts: hosts, access: Access{
		Installation: app.Installation, Requested: permissions, Granted: out.Permissions, Expires: out.ExpiresAt,
	}}
	if len(out.Repositories) == 1 {
		t.access.RepositoryID = out.Repositories[0].ID
	}
	if len(repos) == 1 {
		t.access.Repository = app.Account + "/" + strings.ToLower(repos[0])
	}
	granted := make([]string, len(out.Repositories))
	for i, r := range out.Repositories {
		granted[i] = strings.ToLower(r.FullName)
	}
	if !asAsked(out.Permissions, permissions) {
		return nil, nil, t.mismatch(ctx, s)
	}
	return t, granted, nil
}

// asAsked reports whether GitHub granted exactly the permissions asked
// for, allowing metadata: read, which every installation token carries and
// which GitHub lists whatever was asked (ADR-0021 item 3). Anything more is
// a wider grant.
func asAsked(granted, asked map[string]string) bool {
	if maps.Equal(granted, asked) {
		return true
	}
	if _, ok := asked["metadata"]; ok || granted["metadata"] != "read" {
		return false
	}
	g := maps.Clone(granted)
	delete(g, "metadata")
	return maps.Equal(g, asked)
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
// second time when the first fails, and clears it. It runs on its own
// deadline, whatever ctx's. A token that could not be revoked expires
// within the hour GitHub set; the caller reports it (ADR-0021 item 6).
func (t *Installation) Revoke(ctx context.Context, s Sender) error {
	defer clear(t.token)
	t.access.Revocation = "revoke_failed"
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	var err error
	for range 2 {
		var res egress.Response
		if res, err = send(ctx, s, t.base, t.hosts, http.MethodDelete, "/installation/token", nil, t.token); err == nil && res.Status == http.StatusNoContent {
			t.access.Revocation = "revoked"
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

// ReadOnly reports whether every permission is read: all that a read, a
// verification read or a fact read may be minted with (HR-203).
func ReadOnly(permissions map[string]string) bool {
	for _, level := range permissions {
		if level != "read" {
			return false
		}
	}
	return true
}
