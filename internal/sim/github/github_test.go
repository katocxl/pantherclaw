// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// signJWT signs an App JWT as the gateway's broker does.
func signJWT(t *testing.T, key *rsa.PrivateKey, alg string, claims map[string]any) string {
	t.Helper()
	head, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(head) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type world struct {
	t    *testing.T
	sim  *Server
	srv  *httptest.Server
	head string
}

// newWorld is acme/payments and acme/other, the App installed on acme for
// both with contents and pull requests write, and a branch fix/a with one
// more commit than main.
func newWorld(t *testing.T) *world {
	t.Helper()
	sim := New(slog.New(slog.DiscardHandler))
	sim.RegisterApp(42, "Iv23liSIM", &testKey.PublicKey)
	sim.Install(Installation{ID: 7, Account: "acme", Repos: []string{"payments", "other"}, Permissions: map[string]string{
		"contents": "write", "pull_requests": "write", "metadata": "read",
	}})
	sim.CreateRepo("acme/payments", "main", map[string]string{"README.md": "# payments\n", ".github/workflows/deploy.yml": "on: push\n"})
	sim.CreateRepo("acme/other", "main", map[string]string{"README.md": "# other\n"})
	head := sim.Push("acme/payments", "fix/a", map[string]string{"parser.go": "package parser\n"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	return &world{t: t, sim: sim, srv: srv, head: head}
}

func (w *world) do(method, path, auth, body string) (int, map[string]any) {
	w.t.Helper()
	req, _ := http.NewRequestWithContext(w.t.Context(), method, w.srv.URL+path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (w *world) jwt() string {
	now := time.Now()
	return signJWT(w.t, testKey, "RS256", map[string]any{"iss": "Iv23liSIM", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix()})
}

// mint asks for a token for repos and permissions.
func (w *world) mint(body string) (int, string) {
	w.t.Helper()
	status, out := w.do("POST", "/app/installations/7/access_tokens", "Bearer "+w.jwt(), body)
	tok, _ := out["token"].(string)
	return status, tok
}

// TestInstallationTokensAreScoped: a token reaches only the repositories
// and permissions it was minted for, is opaque and about 520 characters,
// and every request records the scope of the token it used.
func TestInstallationTokensAreScoped(t *testing.T) {
	w := newWorld(t)
	status, tok := w.mint(`{"repositories":["payments"],"permissions":{"contents":"read"}}`)
	if status != http.StatusCreated || !strings.HasPrefix(tok, "ghs_") || len(tok) != 520 {
		t.Fatalf("mint: %d %d", status, len(tok))
	}
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/repos/acme/payments/contents/README.md", http.StatusOK},
		{"GET", "/repos/acme/payments/contents/.github/workflows/deploy.yml", http.StatusOK},
		{"GET", "/repos/acme/payments", http.StatusOK}, // metadata comes with every token
		{"GET", "/repos/acme/other/contents/README.md", http.StatusNotFound},
		{"PATCH", "/repos/acme/payments", http.StatusForbidden},
		{"POST", "/repos/acme/payments/git/refs", http.StatusForbidden},
	} {
		if got, _ := w.do(c.method, c.path, "Bearer "+tok, `{}`); got != c.want {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, got, c.want)
		}
	}
	reqs := w.sim.Requests()
	last := reqs[len(reqs)-1]
	if last.Token != Fingerprint(tok) || last.Installation != 7 || !slices.Equal(last.Repos, []string{"acme/payments"}) ||
		!maps.Equal(last.Permissions, map[string]string{"contents": "read"}) || !last.Write || last.Status != http.StatusForbidden {
		t.Fatalf("recorded %+v", last)
	}
	if got := w.sim.Tokens(); len(got) != 1 || got[0].Uses != 6 {
		t.Fatalf("tokens %+v", got)
	}
}

// TestMintingStaysWithinTheInstallation: no token for a repository or a
// permission the installation does not have.
func TestMintingStaysWithinTheInstallation(t *testing.T) {
	w := newWorld(t)
	for name, body := range map[string]string{
		"another repository":    `{"repositories":["secret"],"permissions":{"contents":"read"}}`,
		"another permission":    `{"repositories":["payments"],"permissions":{"administration":"write"}}`,
		"a higher level":        `{"repositories":["payments"],"permissions":{"metadata":"write"}}`,
		"an unknown body field": `{"repositories":["payments"],"repository_ids":[1]}`,
	} {
		if status, tok := w.mint(body); status != http.StatusUnprocessableEntity || tok != "" {
			t.Errorf("%s: %d", name, status)
		}
	}
	// Without a body the token gets everything the installation has.
	if status, _ := w.mint(``); status != http.StatusCreated {
		t.Fatalf("unscoped: %d", status)
	}
	if got := w.sim.Tokens(); len(got) != 1 || len(got[0].Repos) != 2 {
		t.Fatalf("tokens %+v", got)
	}
}

// TestAppJWTsAreCheckedAsGitHubDoes: signed by the App's key with RS256,
// issued by its id or client id, unexpired and at most ten minutes ahead.
func TestAppJWTsAreCheckedAsGitHubDoes(t *testing.T) {
	w := newWorld(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	ok := map[string]any{"iss": "42", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix()}
	with := func(k string, v any) map[string]any {
		c := maps.Clone(ok)
		c[k] = v
		return c
	}
	for name, jwt := range map[string]string{
		"another key":       signJWT(t, other, "RS256", ok),
		"another algorithm": signJWT(t, testKey, "RS512", ok),
		"another issuer":    signJWT(t, testKey, "RS256", with("iss", "43")),
		"expired":           signJWT(t, testKey, "RS256", with("exp", now.Add(-time.Second).Unix())),
		"too far ahead":     signJWT(t, testKey, "RS256", with("exp", now.Add(11*time.Minute).Unix())),
		"issued later":      signJWT(t, testKey, "RS256", with("iat", now.Add(5*time.Minute).Unix())),
		"not a JWT":         "ghs_x",
	} {
		if status, _ := w.do("POST", "/app/installations/7/access_tokens", "Bearer "+jwt, `{}`); status != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, status)
		}
	}
	if status, _ := w.do("POST", "/app/installations/7/access_tokens", "Bearer "+signJWT(t, testKey, "RS256", ok), `{}`); status != http.StatusCreated {
		t.Fatalf("numeric issuer: %d", status)
	}
	if got := w.sim.AppJWTs(); len(got) != 1 || got[0].Issuer != "42" {
		t.Fatalf("jwts %+v", got)
	}
}

// TestRevokedTokensAreRefused: DELETE /installation/token ends a token at
// once.
func TestRevokedTokensAreRefused(t *testing.T) {
	w := newWorld(t)
	_, tok := w.mint(`{"repositories":["payments"],"permissions":{"contents":"read"}}`)
	if status, _ := w.do("DELETE", "/installation/token", "token "+tok, ""); status != http.StatusNoContent {
		t.Fatalf("revoke: %d", status)
	}
	if status, _ := w.do("GET", "/repos/acme/payments/contents/README.md", "Bearer "+tok, ""); status != http.StatusUnauthorized {
		t.Fatalf("after revocation: %d", status)
	}
	if got := w.sim.Tokens(); len(got) != 1 || !got[0].Revoked {
		t.Fatalf("tokens %+v", got)
	}
	w.sim.AddToken("ghp_found", "mallory", []string{"acme/payments"}, map[string]string{"contents": "write"})
	if status, _ := w.do("DELETE", "/installation/token", "token ghp_found", ""); status != http.StatusForbidden {
		t.Fatalf("a personal token: %d", status)
	}
}

// TestBranchesAndRefs: a branch is created at an existing commit only.
func TestBranchesAndRefs(t *testing.T) {
	w := newWorld(t)
	_, tok := w.mint(`{"repositories":["payments"],"permissions":{"contents":"write"}}`)
	auth := "Bearer " + tok
	main := w.sim.Branch("acme/payments", "main")
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"ref":"refs/heads/fix/b","sha":"` + main + `"}`, http.StatusCreated},
		{`{"ref":"refs/heads/fix/b","sha":"` + main + `"}`, http.StatusUnprocessableEntity}, // exists
		{`{"ref":"refs/heads/fix/c","sha":"0000000000000000000000000000000000000000"}`, http.StatusUnprocessableEntity},
		{`{"ref":"refs/tags/v1","sha":"` + main + `"}`, http.StatusUnprocessableEntity},
	} {
		if status, _ := w.do("POST", "/repos/acme/payments/git/refs", auth, c.body); status != c.want {
			t.Errorf("%s: %d, want %d", c.body, status, c.want)
		}
	}
	if w.sim.Branch("acme/payments", "fix/b") != main {
		t.Fatal("branch not created at main")
	}
}

// TestContentsBranchesAndSettings: files come back base64 as GitHub sends
// them, directories as listings, and a settings change takes only the
// fields the API documents.
func TestContentsBranchesAndSettings(t *testing.T) {
	w := newWorld(t)
	w.sim.Install(Installation{ID: 8, Account: "acme", Repos: []string{"payments"}, Permissions: map[string]string{
		"contents": "read", "administration": "write",
	}})
	status, out := w.do("POST", "/app/installations/8/access_tokens", "Bearer "+w.jwt(), `{"repositories":["payments"]}`)
	if status != http.StatusCreated {
		t.Fatalf("mint: %d", status)
	}
	auth := "Bearer " + out["token"].(string)
	status, file := w.do("GET", "/repos/acme/payments/contents/README.md?ref=main", auth, "")
	if status != http.StatusOK || file["content"] != base64.StdEncoding.EncodeToString([]byte("# payments\n")) || file["type"] != "file" {
		t.Fatalf("file: %d %v", status, file)
	}
	if status, _ := w.do("GET", "/repos/acme/payments/contents/parser.go?ref="+w.head, auth, ""); status != http.StatusOK {
		t.Fatalf("file at a commit: %d", status)
	}
	if status, _ := w.do("GET", "/repos/acme/payments/contents/parser.go", auth, ""); status != http.StatusNotFound {
		t.Fatalf("file on another branch: %d", status)
	}
	req, _ := http.NewRequestWithContext(t.Context(), "GET", w.srv.URL+"/repos/acme/payments/contents/.github", nil)
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var dir []map[string]any
	_ = json.UnmarshalRead(resp.Body, &dir)
	_ = resp.Body.Close()
	if len(dir) != 1 || dir[0]["type"] != "dir" || dir[0]["path"] != ".github/workflows" {
		t.Fatalf("directory: %v", dir)
	}
	if status, _ := w.do("PATCH", "/repos/acme/payments", auth, `{"delete_branch_on_merge":true,"default_branch":"fix/a"}`); status != http.StatusOK {
		t.Fatalf("settings: %d", status)
	}
	if def, set := w.sim.RepoSettings("acme/payments"); def != "fix/a" || !set.DeleteBranchOnMerge || !set.AllowMergeCommit {
		t.Fatalf("settings %s %+v", def, set)
	}
	if status, _ := w.do("PATCH", "/repos/acme/payments", auth, `{"visibility":"public"}`); status != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown setting: %d", status)
	}
}
