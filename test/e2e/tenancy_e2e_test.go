// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/server"
)

// idp signs a person in at an authorization URL and returns the redirect
// back to PantherClaw.
type idp struct {
	issuer, clientID, secret string
	signIn                   func(t *testing.T, b *http.Client, authURL, subject, email string) string
}

func inProcessIdP(t *testing.T) idp {
	p := oidctest.New(t)
	return idp{
		issuer: p.Issuer(), clientID: p.ClientID, secret: p.ClientSecret,
		signIn: func(t *testing.T, b *http.Client, authURL, subject, email string) string {
			t.Helper()
			p.SignIn(oidctest.User{Subject: subject, Email: email, EmailVerified: true, Name: subject})
			res := get(t, b, authURL)
			return res.Location
		},
	}
}

// mockOAuth2IdP drives navikt/mock-oauth2-server's login form (CI service).
func mockOAuth2IdP(base string) idp {
	return idp{
		issuer: strings.TrimRight(base, "/") + "/default", clientID: "pantherclaw", secret: "mock-secret",
		signIn: func(t *testing.T, b *http.Client, authURL, subject, email string) string {
			t.Helper()
			claims, _ := json.Marshal(map[string]any{"email": email, "email_verified": true, "name": subject})
			res := post(t, b, authURL, url.Values{"username": {subject}, "claims": {string(claims)}}, nil)
			return res.Location
		},
	}
}

// hop is a read and closed response: its status and redirect target.
type hop struct {
	StatusCode int
	Location   string
}

func get(t *testing.T, b *http.Client, u string) hop {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return hop{StatusCode: res.StatusCode, Location: res.Header.Get("Location")}
}

func post(t *testing.T, b *http.Client, u string, form url.Values, hdr map[string]string) hop {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return hop{StatusCode: res.StatusCode, Location: res.Header.Get("Location")}
}

// m2Stack is a running server with an OIDC provider configured.
type m2Stack struct {
	url, cfg string
	idp      idp
}

func startM2(t *testing.T, p idp) *m2Stack {
	t.Helper()
	d := dbtest.New(t)
	dir := t.TempDir()
	kek := filepath.Join(dir, "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	apiAddr := freeAddr(t)
	public := "http://" + apiAddr
	b, err := json.Marshal(map[string]any{
		"role": "all", "log": map[string]any{"level": "warn"}, "http": map[string]any{"addr": apiAddr},
		"database": map[string]any{
			"host": d.App.Host, "port": d.App.Port, "name": d.Name, "sslmode": "disable",
			"app_password_file":      writeFile(t, dir, "app-pw", d.App.Password.Reveal()),
			"migrator_password_file": writeFile(t, dir, "mig-pw", d.Migrator.Password.Reveal()),
			"max_conns":              10,
		},
		"kek_files": []string{kek}, "worker_concurrency": 2,
		"auth": map[string]any{
			"public_url": public, "api_key_env": "test",
			"oidc_providers": []map[string]any{{
				"name": "test", "issuer": p.issuer, "client_id": p.clientID, "allow_insecure_loopback": true,
				"client_secret_file": writeFile(t, dir, "idp-secret", []byte(p.secret)),
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := writeFile(t, dir, "server.json", b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var logs syncBuffer
	go func() {
		defer close(done)
		if err := runServer(ctx, cfg, &logs); err != nil {
			t.Errorf("%v\n%s", err, logs.String())
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not stop")
		}
	})
	waitReady(t, public, &logs)
	return &m2Stack{url: public, cfg: cfg, idp: p}
}

// user is one person's pclaw: its own config directory.
type user struct {
	s       *m2Stack
	dir     string
	subject string
	email   string
}

func (s *m2Stack) user(t *testing.T, subject, email string) *user {
	return &user{s: s, dir: t.TempDir(), subject: subject, email: email}
}

func (u *user) env(extra ...string) pclaw.Env {
	// The file store: these tests read credentials.json and must not
	// touch the machine's real OS keychain.
	m := map[string]string{"PANTHERCLAW_CONFIG_DIR": u.dir, "PANTHERCLAW_CREDENTIAL_STORE": "file"}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func (u *user) pclaw(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := pclaw.Run(context.Background(), args, &out, &errb, u.env(), pclaw.Options{})
	return code, out.String(), errb.String()
}

var signInLink = regexp.MustCompile(`(http://\S+/device\?org=\S+&user_code=[A-Z-]+)`)

// login runs `pclaw login` while a browser confirms the code and signs in at
// the provider.
func (u *user) login(t *testing.T, org, invitation string) {
	t.Helper()
	var out syncBuffer
	var errb bytes.Buffer
	done := make(chan int, 1)
	args := []string{"login", "--server", u.s.url, "--org", org, "--no-browser"}
	if invitation != "" {
		args = append(args, "--invitation", invitation)
	}
	go func() { done <- pclaw.Run(context.Background(), args, &out, &errb, u.env(), pclaw.Options{}) }()
	var link string
	deadline := time.Now().Add(20 * time.Second)
	for link == "" && time.Now().Before(deadline) {
		if m := signInLink.FindStringSubmatch(out.String()); m != nil {
			link = m[1]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if link == "" {
		t.Fatalf("pclaw printed no sign-in link: %s %s", out.String(), errb.String())
	}
	jar, _ := cookiejar.New(nil)
	b := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	lu, _ := url.Parse(link)
	res := post(t, b, u.s.url+"/device", url.Values{"org": {lu.Query().Get("org")}, "user_code": {lu.Query().Get("user_code")}},
		map[string]string{"Origin": u.s.url})
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm: %d", res.StatusCode)
	}
	callback := u.s.idp.signIn(t, b, res.Location, u.subject, u.email)
	if res := get(t, b, callback); res.StatusCode != http.StatusOK {
		t.Fatalf("callback %d for %s", res.StatusCode, u.email)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("pclaw login exited %d: %s %s", code, out.String(), errb.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("pclaw login did not finish")
	}
}

var (
	orgCreated = regexp.MustCompile(`created organization ([0-9a-f-]{36})`)
	pciToken   = regexp.MustCompile(`(pci_[0-9a-f]{32}_[0-9A-Za-z]{43})`)
)

func field(t *testing.T, out, name string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("not JSON: %q", out)
	}
	var walk func(any) string
	walk = func(v any) string {
		x, ok := v.(map[string]any)
		if !ok {
			return ""
		}
		if s, ok := x[name].(string); ok {
			return s
		}
		for _, c := range x {
			if s := walk(c); s != "" {
				return s
			}
		}
		return ""
	}
	return walk(m)
}

// m2Scenario is the M2 exit criterion: authenticated, authorized tenancy
// administration via Connect and the CLI, for people and services.
func m2Scenario(t *testing.T, s *m2Stack) {
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "create", "--config", s.cfg, "--name", "Acme"}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org create: %d %s", code, errb.String())
	}
	org := orgCreated.FindStringSubmatch(out.String())[1]
	bootstrap := pciToken.FindString(out.String())

	alice := s.user(t, "alice", "alice@example.test")
	alice.login(t, org, bootstrap)
	if code, o, e := alice.pclaw(t, "whoami"); code != 0 || !strings.Contains(o, "org_admin") || !strings.Contains(o, "Acme") {
		t.Fatalf("alice whoami: %d %s %s", code, o, e)
	}
	// The bootstrap token is single use.
	mallory := s.user(t, "mallory", "mallory@example.test")
	if code, _, e := mallory.pclaw(t, "login", "--server", s.url, "--org", org, "--invitation", bootstrap, "--no-browser"); code != 1 || !strings.Contains(e, "invalid_grant") {
		t.Fatalf("reused bootstrap token: %d %s", code, e)
	}

	code, o, e := alice.pclaw(t, "team", "create", "--slug", "payments", "--name", "Payments")
	if code != 0 {
		t.Fatalf("team create: %s %s", o, e)
	}
	team := field(t, o, "id")
	if code, o, e := alice.pclaw(t, "env", "create", "--team", team, "--slug", "prod", "--name", "Production", "--kind", "prod"); code != 0 {
		t.Fatalf("env create: %s %s", o, e)
	}
	_, o, _ = alice.pclaw(t, "invite", "create", "--email", "bob@example.test", "--role", "viewer")
	bobInvite := field(t, o, "token")

	bob := s.user(t, "bob", "bob@example.test")
	bob.login(t, org, bobInvite)
	if code, o, _ := bob.pclaw(t, "team", "list"); code != 0 || !strings.Contains(o, "payments") {
		t.Fatalf("viewer team list: %d %s", code, o)
	}
	if code, _, e := bob.pclaw(t, "team", "create", "--slug", "x", "--name", "X"); code != 1 || !strings.Contains(e, "permission denied") {
		t.Fatalf("viewer team create: %d %s", code, e)
	}

	// Service account with a key pair (private_key_jwt) and a scoped API key.
	_, o, _ = alice.pclaw(t, "sa", "create", "--name", "ci")
	sa := field(t, o, "id")
	if code, _, e := alice.pclaw(t, "role", "bind", "--role", "viewer", "--sa", sa); code != 0 {
		t.Fatalf("bind viewer to sa: %s", e)
	}
	if code, _, e := alice.pclaw(t, "role", "bind", "--role", "approver", "--sa", sa); code != 1 || !strings.Contains(e, "HUMAN_ONLY_ROLE") {
		t.Fatalf("approver for a service account: %d %s", code, e)
	}
	keyFile := filepath.Join(alice.dir, "ci-key.json")
	if code, _, e := alice.pclaw(t, "sa", "key-generate", sa, "--out", keyFile); code != 0 {
		t.Fatalf("key-generate: %s", e)
	}
	code, o, e = alice.pclaw(t, "sa", "token", "--key-file", keyFile)
	if code != 0 || !strings.Contains(o, `"token_type":"Bearer"`) {
		t.Fatalf("sa token: %d %s %s", code, o, e)
	}
	if fi, err := os.Stat(keyFile); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("key file: %v", err)
	}
	_, o, _ = alice.pclaw(t, "apikey", "create", "--sa", sa, "--name", "reader", "--scope", "team.read")
	secret := field(t, o, "secret")
	robot := s.user(t, "robot", "")
	runAs := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := pclaw.Run(context.Background(), args, &out, &errb,
			robot.env("PANTHERCLAW_SERVER", s.url, "PANTHERCLAW_API_KEY", secret), pclaw.Options{})
		return code, out.String(), errb.String()
	}
	if code, o, e := runAs("team", "list"); code != 0 || !strings.Contains(o, "payments") {
		t.Fatalf("API key team list: %d %s %s", code, o, e)
	}
	if code, _, e := runAs("env", "list"); code != 1 || !strings.Contains(e, "permission denied") {
		t.Fatalf("API key outside its scopes: %d %s", code, e)
	}

	// Disabling bob stops his session at once.
	_, o, _ = alice.pclaw(t, "user", "list")
	var users struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	_ = json.Unmarshal([]byte(o), &users)
	bobID := ""
	for _, u := range users.Users {
		if u.Email == "bob@example.test" {
			bobID = u.ID
		}
	}
	if code, _, e := alice.pclaw(t, "user", "disable", bobID); code != 0 {
		t.Fatalf("disable bob: %s", e)
	}
	if code, _, e := bob.pclaw(t, "whoami"); code != 1 || !strings.Contains(e, "unauthenticated") {
		t.Fatalf("disabled bob: %d %s", code, e)
	}
	if code, _, _ := alice.pclaw(t, "logout"); code != 0 {
		t.Fatal("logout")
	}
	if code, _, _ := alice.pclaw(t, "whoami"); code != 1 {
		t.Fatal("whoami after logout")
	}
}

// TestE2E_M2_LoginTenancyAndServiceAuth runs the scenario with the
// in-process OpenID provider.
func TestE2E_M2_LoginTenancyAndServiceAuth(t *testing.T) {
	m2Scenario(t, startM2(t, inProcessIdP(t)))
}

// TestE2E_M2_InteropMockOAuth2Server runs the scenario against
// navikt/mock-oauth2-server, a third-party OpenID provider (CI service
// container; set PC_TEST_MOCK_OIDC_URL locally to run it).
func TestE2E_M2_InteropMockOAuth2Server(t *testing.T) {
	base, ok := os.LookupEnv("PC_TEST_MOCK_OIDC_URL")
	if !ok || base == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("PC_TEST_MOCK_OIDC_URL must be set in CI")
		}
		t.Skip("PC_TEST_MOCK_OIDC_URL not set (docker compose --profile test starts the mock on 127.0.0.1:8181)")
	}
	p := mockOAuth2IdP(base)
	deadline := time.Now().Add(90 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, p.issuer+"/.well-known/openid-configuration", nil)
		res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("mock OpenID provider at %s is not up: %v", base, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	m2Scenario(t, startM2(t, p))
}
