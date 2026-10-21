// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

const (
	testSecret = "dev-only-test-secret"
	callback   = "http://localhost:8080/oauth2/callback/dev"
)

// devFixture is a running provider, the core's relying party configured
// for it, and a browser with its own cookies that follows no redirect.
type devFixture struct {
	p       *provider
	rp      *oidcrp.Provider
	browser *http.Client
}

func newDevFixture(t *testing.T) *devFixture {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	p, err := newProvider("http://"+ts.Listener.Addr().String(), "pantherclaw", []byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = p.handler()
	ts.Start()
	t.Cleanup(ts.Close)
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	rp, err := oidcrp.New(oidcrp.Config{
		Name: "dev", Issuer: p.issuer, ClientID: "pantherclaw", ClientSecret: pclog.NewSecret([]byte(testSecret)),
		AllowInsecureLoopback: true, HTTPClient: &http.Client{Transport: &http.Transport{}, CheckRedirect: noRedirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &devFixture{p: p, rp: rp, browser: &http.Client{Jar: jar, CheckRedirect: noRedirect}}
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

// answer is a response, read and closed.
type answer struct {
	status int
	header http.Header
	body   string
}

// location is the answer's redirect, parsed.
func (a answer) location() *url.URL {
	u, err := url.Parse(a.header.Get("Location"))
	if err != nil {
		return &url.URL{}
	}
	return u
}

// do sends r from the browser.
func (f *devFixture) do(t *testing.T, r *http.Request) answer {
	t.Helper()
	res, err := f.browser.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer{status: res.StatusCode, header: res.Header, body: string(body)}
}

func (f *devFixture) get(t *testing.T, u string) answer {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f.do(t, r)
}

func (f *devFixture) post(t *testing.T, u string, form url.Values, basicSecret string) answer {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicSecret != "" {
		r.SetBasicAuth("pantherclaw", basicSecret)
	}
	return f.do(t, r)
}

// start begins a sign-in as the server does (state, nonce, PKCE, max_age)
// with extra parameters, and returns the request and the browser's answer.
func (f *devFixture) start(t *testing.T, maxAge time.Duration, extra string) (authnapp.AuthRequest, answer) {
	t.Helper()
	req := authnapp.AuthRequest{State: rand.Text(), Nonce: rand.Text(), Verifier: rand.Text() + rand.Text(), RedirectURI: callback, MaxAge: maxAge}
	u, err := f.rp.AuthCodeURL(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return req, f.get(t, u+extra)
}

// submit signs in as user on the form in page.
func (f *devFixture) submit(t *testing.T, page answer, user string) answer {
	t.Helper()
	m := requestField.FindStringSubmatch(page.body)
	if m == nil {
		t.Fatalf("no sign-in form: %d\n%s", page.status, page.body)
	}
	return f.post(t, f.p.issuer+"/login", url.Values{"request": {m[1]}, "username": {user}, "verified": {"1"}}, "")
}

// finish checks the redirect to the server and exchanges its code as the
// server does.
func (f *devFixture) finish(t *testing.T, req authnapp.AuthRequest, a answer) authnapp.IDClaims {
	t.Helper()
	loc := a.location()
	if a.status != http.StatusFound || !strings.HasPrefix(loc.String(), callback+"?") {
		t.Fatalf("not sent back to the server: %d %s", a.status, loc)
	}
	q := loc.Query()
	if q.Get("state") != req.State || q.Get("iss") != f.p.issuer || q.Get("code") == "" {
		t.Fatalf("the redirect: %v", q)
	}
	claims, err := f.rp.Exchange(context.Background(), q.Get("code"), req.Verifier, callback)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Nonce != req.Nonce || claims.Issuer != f.p.issuer {
		t.Fatalf("claims %+v", claims)
	}
	return claims
}

// TestDevOIDC_AuthTimeIsTheSignInAndMaxAgeAsksAgain (D95, HR-155): through
// the core's relying party, the form's submit time is the ID token's
// auth_time. A later sign-in with the provider's session and no max_age is
// instant and keeps that auth_time, a stale one, which is how a real
// provider answers; max_age older than the session, and prompt=login,
// show the form again, and the new auth_time is the new submit.
func TestDevOIDC_AuthTimeIsTheSignInAndMaxAgeAsksAgain(t *testing.T) {
	f := newDevFixture(t)
	req, page := f.start(t, 5*time.Minute, "")
	if page.status != http.StatusOK || !strings.Contains(page.body, "DEVELOPMENT ONLY") ||
		!strings.Contains(page.header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("the form: %d %s", page.status, page.body)
	}
	before := time.Now().Truncate(time.Second)
	claims := f.finish(t, req, f.submit(t, page, "alice"))
	if claims.Subject != "alice" || claims.Email != "alice@example.test" || !claims.EmailVerified ||
		claims.AuthTime.Before(before) || claims.AuthTime.After(time.Now()) {
		t.Fatalf("first sign-in: %+v (submitted at %v)", claims, before)
	}
	first := claims.AuthTime

	// The provider's session is now ten minutes old.
	f.p.mu.Lock()
	for k, s := range f.p.sessions {
		s.authTime = s.authTime.Add(-10 * time.Minute)
		f.p.sessions[k] = s
	}
	f.p.mu.Unlock()
	req, back := f.start(t, 0, "")
	if claims := f.finish(t, req, back); !claims.AuthTime.Equal(first.Add(-10 * time.Minute)) {
		t.Fatalf("without max_age the session's auth_time is kept: %v, want %v", claims.AuthTime, first.Add(-10*time.Minute))
	}
	req, page = f.start(t, 5*time.Minute, "")
	if page.status != http.StatusOK || !strings.Contains(page.body, "asked for a fresh sign-in") {
		t.Fatalf("max_age older than the session shows no form: %d", page.status)
	}
	before = time.Now().Truncate(time.Second)
	if claims := f.finish(t, req, f.submit(t, page, "alice")); claims.AuthTime.Before(before) {
		t.Fatalf("auth_time after signing in again: %v, want at least %v", claims.AuthTime, before)
	}
	if _, a := f.start(t, 5*time.Minute, ""); a.status != http.StatusFound {
		t.Fatalf("a fresh session within max_age asks again: %d %s", a.status, a.body)
	}
	if _, a := f.start(t, 5*time.Minute, "&prompt=login"); a.status != http.StatusOK || !requestField.MatchString(a.body) {
		t.Fatalf("prompt=login shows no form: %d", a.status)
	}
}

// TestDevOIDC_RefusesWhatARealProviderRefuses: an unknown client, a
// redirect that is not on a loopback host, no PKCE or nonce, a wrong
// client secret, a wrong verifier and a used code; prompt=none without a
// session answers login_required; userinfo needs the access token.
func TestDevOIDC_RefusesWhatARealProviderRefuses(t *testing.T) {
	f := newDevFixture(t)
	good := url.Values{
		"client_id": {"pantherclaw"}, "response_type": {"code"}, "scope": {"openid email"}, "redirect_uri": {callback},
		"state": {"s"}, "nonce": {"n"}, "code_challenge": {"c"}, "code_challenge_method": {"S256"},
	}
	with := func(k, v string) string {
		q := url.Values{}
		for kk, vv := range good {
			q[kk] = vv
		}
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
		return f.p.issuer + "/authorize?" + q.Encode()
	}
	for name, u := range map[string]string{
		"another client": with("client_id", "other"), "a remote redirect": with("redirect_uri", "https://evil.example/cb"),
	} {
		if a := f.get(t, u); a.status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, a.status)
		}
	}
	for name, u := range map[string]string{
		"no PKCE": with("code_challenge", ""), "plain PKCE": with("code_challenge_method", "plain"), "no nonce": with("nonce", ""),
		"prompt=none, signed out": with("prompt", "none"), "bad max_age": with("max_age", "-1"),
	} {
		a := f.get(t, u)
		if q := a.location().Query(); a.status != http.StatusFound || q.Get("error") == "" || q.Get("code") != "" {
			t.Errorf("%s: %d %s", name, a.status, a.location())
		}
	}

	req, page := f.start(t, 0, "")
	code := f.submit(t, page, "bob").location().Query().Get("code")
	token := func(secret, verifier string) int {
		t.Helper()
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "code_verifier": {verifier}}
		return f.post(t, f.p.issuer+"/token", form, secret).status
	}
	if got := token("wrong", req.Verifier); got != http.StatusUnauthorized {
		t.Errorf("a wrong secret: %d", got)
	}
	if got := token(testSecret, "not-the-verifier"); got != http.StatusBadRequest {
		t.Errorf("a wrong verifier: %d", got)
	}
	if got := token(testSecret, req.Verifier); got != http.StatusBadRequest {
		t.Errorf("a code used (by the wrong verifier) is gone: %d", got)
	}
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.p.issuer+"/userinfo", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer nope")
	if a := f.do(t, r); a.status != http.StatusUnauthorized {
		t.Errorf("userinfo with an unknown token: %d", a.status)
	}
}

// TestDevOIDC_ListensOnlyOnLoopback: it signs anyone in, so it refuses any
// address that is not loopback.
func TestDevOIDC_ListensOnlyOnLoopback(t *testing.T) {
	for addr, want := range map[string]string{
		"127.0.0.1:8282": "127.0.0.1:8282", "[::1]:8282": "[::1]:8282", "localhost:8282": "127.0.0.1:8282",
		"0.0.0.0:8282": "", ":8282": "", "192.168.1.20:8282": "", "example.test:8282": "", "127.0.0.1:0": "", "127.0.0.1": "",
	} {
		got, err := loopbackAddr(addr)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("%q: %q, %v; want %q", addr, got, err, want)
		}
	}
	var errb bytes.Buffer
	if code := run([]string{"--addr", "0.0.0.0:8282", "--client-secret-file", "x"}, &errb); code != 2 || !strings.Contains(errb.String(), "loopback") {
		t.Errorf("run on 0.0.0.0: %d %s", code, errb.String())
	}
}

// TestDevOIDC_IsInNoBuildOutput: task build and the release build only
// ./cmd/..., no Dockerfile copies or builds this provider, and nothing
// outside it names it.
func TestDevOIDC_IsInNoBuildOutput(t *testing.T) {
	root := filepath.Join("..", "..")
	release, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	mains := regexp.MustCompile(`(?m)^\s*main:\s*(\S+)`).FindAllSubmatch(release, -1)
	if len(mains) == 0 {
		t.Fatal("no builds in .goreleaser.yaml")
	}
	for _, m := range mains {
		if !strings.HasPrefix(string(m[1]), "./cmd/") {
			t.Errorf("the release builds %s, outside ./cmd/", m[1])
		}
	}
	tasks, err := os.ReadFile(filepath.Join(root, "Taskfile.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(tasks, []byte("go build -trimpath -o bin/ ./cmd/...")) {
		t.Error("task build no longer builds only ./cmd/...: check that it leaves test/devoidc out")
	}
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "node_modules", "devoidc":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		build := strings.HasSuffix(name, "Dockerfile") || strings.HasSuffix(name, ".Dockerfile") || name == ".goreleaser.yaml" ||
			strings.HasPrefix(filepath.ToSlash(path), "../../cmd/") && strings.HasSuffix(name, ".go")
		if !build {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("devoidc")) {
			t.Errorf("%s names the development provider", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
