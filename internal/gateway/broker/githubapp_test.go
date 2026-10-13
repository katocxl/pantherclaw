// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

type ghWorld struct {
	sim    *github.Server
	srv    *httptest.Server
	client *egress.Client
	app    domain.GitHubApp
	hosts  []string
}

func newGitHub(t *testing.T) *ghWorld {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sim := github.New(slog.New(slog.DiscardHandler))
	sim.RegisterApp(42, "Iv23liTest", &key.PublicKey)
	sim.Install(github.Installation{ID: 7, Account: "acme", Repos: []string{"payments", "other"}, Permissions: map[string]string{
		"contents": "write", "pull_requests": "write", "metadata": "read",
	}})
	sim.CreateRepo("acme/payments", "main", map[string]string{"README.md": "# payments\n"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	c, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return &ghWorld{
		sim: sim, srv: srv, client: c, hosts: []string{u.Host},
		app: domain.GitHubApp{V: 1, Issuer: "Iv23liTest", Installation: 7, Account: "acme", PrivateKey: pemKey},
	}
}

func (w *ghWorld) get(t *testing.T, tok *Installation, path string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+path, nil)
	if err := tok.Place(req); err != nil {
		t.Fatal(err)
	}
	res, err := w.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res.Status
}

// TestHR203_EachActionGetsATokenForOneRepositoryAndItsPermissions: the
// token is minted for exactly the target repository and the operation's
// declared permissions, reaches nothing else, and is revoked after use.
func TestHR203_EachActionGetsATokenForOneRepositoryAndItsPermissions(t *testing.T) {
	w := newGitHub(t)
	ctx := context.Background()
	tok, err := MintInstallationToken(ctx, w.client, w.srv.URL, w.hosts, w.app, "acme", "payments", map[string]string{"contents": "read"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Token()) != 520 || !strings.HasPrefix(string(tok.Token()), "ghs_") {
		t.Fatalf("token of %d bytes", len(tok.Token()))
	}
	for path, want := range map[string]int{
		"/repos/acme/payments/contents/README.md": http.StatusOK,
		"/repos/acme/other/contents/README.md":    http.StatusNotFound,  // another repository of the installation
		"/repos/acme/payments/pulls/1":            http.StatusForbidden, // a permission it was not minted with
	} {
		if got := w.get(t, tok, path); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	fp := github.Fingerprint(string(tok.Token()))
	if err := tok.Revoke(ctx, w.client); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(tok.Token(), func(b byte) bool { return b != 0 }) {
		t.Fatal("the token is not cleared after revocation")
	}
	tokens := w.sim.Tokens()
	if len(tokens) != 1 || !tokens[0].Revoked || !slices.Equal(tokens[0].Repos, []string{"acme/payments"}) ||
		!maps.Equal(tokens[0].Permissions, map[string]string{"contents": "read", "metadata": "read"}) {
		t.Fatalf("minted %+v", tokens)
	}
	mint := w.sim.Requests()[0]
	if mint.Token != fp || !slices.Equal(mint.Repos, []string{"acme/payments"}) {
		t.Fatalf("mint recorded %+v", mint)
	}
	// A second action mints its own token: nothing is cached.
	again, err := MintInstallationToken(ctx, w.client, w.srv.URL, w.hosts, w.app, "acme", "payments", map[string]string{"contents": "read"}, time.Now())
	if err != nil || github.Fingerprint(string(again.Token())) == fp {
		t.Fatalf("second token: %v", err)
	}
}

// TestHR203_NoTokenOutsideTheAction: no permissions declared, another
// account, a permission the installation lacks, or a token request to a
// host the credential is not bound to: nothing is minted.
func TestHR203_NoTokenOutsideTheAction(t *testing.T) {
	w := newGitHub(t)
	ctx := context.Background()
	for name, c := range map[string]struct {
		owner, repo string
		perms       map[string]string
		hosts       []string
		want        error
	}{
		"no permissions":        {"acme", "payments", nil, w.hosts, ErrScope},
		"another account":       {"evil", "payments", map[string]string{"contents": "read"}, w.hosts, ErrAccount},
		"beyond the install":    {"acme", "payments", map[string]string{"administration": "write"}, w.hosts, ErrMint},
		"a repository it lacks": {"acme", "secret", map[string]string{"contents": "read"}, w.hosts, ErrMint},
		"an unbound host":       {"acme", "payments", map[string]string{"contents": "read"}, []string{"api.github.com"}, ErrNotBound},
	} {
		if _, err := MintInstallationToken(ctx, w.client, w.srv.URL, c.hosts, w.app, c.owner, c.repo, c.perms, time.Now()); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := w.sim.Tokens(); len(got) != 0 {
		t.Fatalf("minted %+v", got)
	}
}

// TestHR204_AppJWTsLiveAtMostTenMinutes: the JWT is backdated a minute and
// expires nine minutes ahead, and a JWT signed with another key is refused
// by GitHub, so nothing is minted.
func TestHR204_AppJWTsLiveAtMostTenMinutes(t *testing.T) {
	w := newGitHub(t)
	now := time.Now().Truncate(time.Second)
	tok, err := MintInstallationToken(context.Background(), w.client, w.srv.URL, w.hosts, w.app, "acme", "payments", map[string]string{"contents": "read"}, now)
	if err != nil {
		t.Fatal(err)
	}
	_ = tok.Revoke(context.Background(), w.client)
	jwts := w.sim.AppJWTs()
	if len(jwts) != 1 || !jwts[0].IssuedAt.Equal(now.Add(-time.Minute)) || jwts[0].Expires.Sub(now) > 10*time.Minute || jwts[0].Issuer != "Iv23liTest" {
		t.Fatalf("jwt %+v", jwts)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := w.app
	forged.PrivateKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	if _, err := MintInstallationToken(context.Background(), w.client, w.srv.URL, w.hosts, forged, "acme", "payments", map[string]string{"contents": "read"}, now); !errors.Is(err, ErrMint) {
		t.Fatalf("another key: %v", err)
	}
}

// TestHR203_AWiderGrantIsRevokedAndRefused: GitHub answering with more
// repositories or permissions than asked is CREDENTIAL_SCOPE_MISMATCH: the
// token is revoked at once and never placed (ADR-0021 item 3). The one
// permission GitHub adds to every token, metadata: read, is the baseline,
// not a wider grant.
func TestHR203_AWiderGrantIsRevokedAndRefused(t *testing.T) {
	w := newGitHub(t)
	for _, c := range []struct {
		granted string
		ok      bool
	}{
		{`{"contents":"read"}`, true},
		{`{"contents":"read","metadata":"read"}`, true},
		{`{"contents":"write"}`, false},
		{`{"contents":"read","metadata":"write"}`, false},
		{`{"contents":"read","metadata":"read","issues":"read"}`, false},
		{`{"metadata":"read"}`, false},
	} {
		var revoked int
		fake := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost:
				rw.WriteHeader(http.StatusCreated)
				_, _ = rw.Write([]byte(`{"token":"ghs_granted","permissions":` + c.granted + `,"repositories":[{"full_name":"acme/payments"}]}`))
			case r.Method == http.MethodDelete && r.Header.Get("Authorization") == "Bearer ghs_granted":
				revoked++
				rw.WriteHeader(http.StatusNoContent)
			}
		}))
		cl, err := egress.NewClient(fake.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(fake.URL)
		tok, err := MintInstallationToken(context.Background(), cl, fake.URL, []string{u.Host}, w.app, "acme", "payments", map[string]string{"contents": "read"}, time.Now())
		switch {
		case c.ok && (err != nil || revoked != 0):
			t.Errorf("%s: %v, revoked %d", c.granted, err, revoked)
		case !c.ok && (!errors.Is(err, ErrScopeMismatch) || tok != nil || revoked != 1):
			t.Errorf("wider grant %s: %v, revoked %d", c.granted, err, revoked)
		}
		fake.Close()
	}
}

// TestHR203_RevocationOutlivesTheDispatch: a token is revoked even when the
// dispatch's context has ended (a long target call, an agent that went
// away), on the revocation's own deadline.
func TestHR203_RevocationOutlivesTheDispatch(t *testing.T) {
	w := newGitHub(t)
	ctx, cancel := context.WithCancel(context.Background())
	tok, err := MintInstallationToken(ctx, w.client, w.srv.URL, w.hosts, w.app, "acme", "payments", map[string]string{"contents": "read"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := tok.Revoke(ctx, w.client); err != nil {
		t.Fatalf("revoke after the dispatch ended: %v", err)
	}
	if got := w.sim.Tokens(); len(got) != 1 || !got[0].Revoked {
		t.Fatalf("tokens %+v", got)
	}
}

// TestHR203_ATokenSaysWhatItAllowedAndWhetherItWasRevoked: a minted token
// carries, for the execution receipt, its installation, repository and
// that repository's id, the permissions requested and granted, and the
// expiry GitHub stated; after Revoke, whether the revocation reached
// GitHub (ADR-0021 items 5 and 6). It never carries the token.
func TestHR203_ATokenSaysWhatItAllowedAndWhetherItWasRevoked(t *testing.T) {
	w := newGitHub(t)
	ctx := context.Background()
	perms := map[string]string{"contents": "read"}
	tok, err := MintInstallationToken(ctx, w.client, w.srv.URL, w.hosts, w.app, "acme", "payments", perms, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a := tok.Access()
	if a.Installation != 7 || a.Repository != "acme/payments" || a.RepositoryID <= 0 || !maps.Equal(a.Requested, perms) ||
		!maps.Equal(a.Granted, map[string]string{"contents": "read", "metadata": "read"}) || time.Until(a.Expires) < 50*time.Minute || a.Revocation != "" {
		t.Fatalf("access %+v", a)
	}
	if err := tok.Revoke(ctx, w.client); err != nil || tok.Access().Revocation != "revoked" {
		t.Fatalf("revoked: %v %+v", err, tok.Access())
	}
	// A revocation that cannot reach GitHub says so (a dispatch's ended
	// context does not stop it, so GitHub is gone here); the token then
	// expires at the time GitHub stated.
	tok, err = MintInstallationToken(ctx, w.client, w.srv.URL, w.hosts, w.app, "acme", "payments", perms, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w.srv.Close()
	if err := tok.Revoke(ctx, w.client); err == nil || tok.Access().Revocation != "revoke_failed" {
		t.Fatalf("an unreachable revocation: %v %+v", err, tok.Access())
	}
}
