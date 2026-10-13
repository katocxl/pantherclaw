// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && github_live

package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The GitHub part of G0 M8 against GitHub itself, with the founder's
// sandbox App: task test:github-live, manual and opt-in, never part of
// task check (docs/runbooks/github-live.md). It makes a branch and a pull
// request in the sandbox repository and closes and deletes them at the end.

// liveGitHub is GitHub and the sandbox App the environment names, or a
// skip when PC_GITHUB_LIVE is not 1.
func liveGitHub(t *testing.T) *githubSim {
	t.Helper()
	if os.Getenv("PC_GITHUB_LIVE") != "1" {
		t.Skip("PC_GITHUB_LIVE is not 1: the live GitHub run is manual (task test:github-live)")
	}
	need := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s is not set (docs/runbooks/github-live.md)", name)
		}
		return v
	}
	inst, err := strconv.ParseInt(need("PC_GITHUB_LIVE_INSTALLATION"), 10, 64)
	if err != nil {
		t.Fatalf("PC_GITHUB_LIVE_INSTALLATION: %v", err)
	}
	raw, err := os.ReadFile(need("PC_GITHUB_LIVE_KEY_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("PC_GITHUB_LIVE_KEY_FILE holds no PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		k, err8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		var ok bool
		if key, ok = k.(*rsa.PrivateKey); err8 != nil || !ok {
			t.Fatalf("PC_GITHUB_LIVE_KEY_FILE is not an RSA key: %v %v", err, err8)
		}
	}
	repo := need("PC_GITHUB_LIVE_REPO")
	account, _, _ := strings.Cut(repo, "/")
	api := os.Getenv("PC_GITHUB_LIVE_API")
	if api == "" {
		api = "https://api.github.com"
	}
	return &githubSim{url: api, key: key, app: need("PC_GITHUB_LIVE_APP"), installation: inst, account: strings.ToLower(account), repo: repo}
}

// direct calls GitHub with an installation token of the sandbox App, past
// PantherClaw: only to set up and clean up what the run needs.
type direct struct {
	api, token string
}

func newDirect(t *testing.T, g *githubSim) *direct {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": g.app})
	signed := enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	d := &direct{api: g.url, token: signed + "." + enc(sig)}
	var tok struct {
		Token string `json:"token"`
	}
	d.do(t, http.MethodPost, "/app/installations/"+strconv.FormatInt(g.installation, 10)+"/access_tokens", "", http.StatusCreated, &tok)
	d.token = tok.Token
	t.Cleanup(func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, d.api+"/installation/token", nil)
		req.Header.Set("Authorization", "Bearer "+d.token)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	})
	return d
}

func (d *direct) do(t *testing.T, method, path, body string, want int, out any) {
	t.Helper()
	if err := d.call(method, path, body, want, out); err != nil {
		t.Fatal(err)
	}
}

// call is do for a cleanup, which reports instead of failing.
func (d *direct) call(method, path, body string, want int, out any) error {
	req, _ := http.NewRequestWithContext(context.Background(), method, d.api+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("GitHub %s %s: %d %s", method, path, resp.StatusCode, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("GitHub %s %s: %w", method, path, err)
		}
	}
	return nil
}

// TestLive_GitHub_MergeIsHeld runs the first steps of §43 against GitHub:
// reading, branching, writing and opening a pull request are allowed and
// run with the App's per-action tokens minted by the gateway; the merge is
// held for an independent code reviewer, the same over MCP and REST, and
// nothing merges.
func TestLive_GitHub_MergeIsHeld(t *testing.T) {
	live := liveGitHub(t)
	d := newDirect(t, live)
	var info struct {
		DefaultBranch string `json:"default_branch"`
	}
	d.do(t, http.MethodGet, "/repos/"+live.repo, "", http.StatusOK, &info)
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	d.do(t, http.MethodGet, "/repos/"+live.repo+"/git/ref/heads/"+url.PathEscape(info.DefaultBranch), "", http.StatusOK, &ref)

	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, github: true, githubAt: live})
	branch := "pantherclaw-live/" + ids.NewV7().String()
	t.Cleanup(func() {
		if err := d.call(http.MethodDelete, "/repos/"+live.repo+"/git/refs/heads/"+branch, "", http.StatusNoContent, nil); err != nil {
			t.Logf("delete the branch %s by hand: %v", branch, err)
		}
	})

	if code, r, _ := s.ghCall(t, http.MethodGet, "/repos/"+live.repo+"/contents/README.md?ref="+url.QueryEscape(info.DefaultBranch), "", ids.NewV7()); code != http.StatusOK {
		t.Fatalf("read: %d %+v", code, r)
	}
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+live.repo+"/git/refs", `{"ref":"refs/heads/`+branch+`","sha":"`+ref.Object.SHA+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("branch: %d %+v", code, r)
	}
	content := base64.StdEncoding.EncodeToString([]byte("written by task test:github-live\n"))
	if code, r, _ := s.ghCall(t, http.MethodPut, "/repos/"+live.repo+"/contents/"+branch+".txt",
		`{"message":"PantherClaw live run","content":"`+content+`","branch":"`+branch+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("write: %d %+v", code, r)
	}
	code, r, raw := s.ghCall(t, http.MethodPost, "/repos/"+live.repo+"/pulls",
		`{"title":"PantherClaw live run","head":"`+branch+`","base":"`+info.DefaultBranch+`"}`, ids.NewV7())
	if code != http.StatusCreated {
		t.Fatalf("open: %d %+v", code, r)
	}
	var pr struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if err := json.Unmarshal([]byte(raw), &pr); err != nil || pr.Number == 0 {
		t.Fatalf("pull request %s: %v", raw, err)
	}
	t.Cleanup(func() {
		if err := d.call(http.MethodPatch, "/repos/"+live.repo+"/pulls/"+strconv.Itoa(pr.Number), `{"state":"closed"}`, http.StatusOK, nil); err != nil {
			t.Logf("close pull request #%d by hand: %v", pr.Number, err)
		}
	})

	mcp := s.ghMergeMCP(t, pr.Number, pr.Head.SHA)
	var mcpDecision string
	var mcpReasons []string
	member(t, mcp, "decision", &mcpDecision)
	member(t, mcp, "reasons", &mcpReasons)
	code, held := s.ghMerge(t, ids.NewV7(), pr.Number, pr.Head.SHA)
	if code != http.StatusForbidden || held.Decision != "REQUIRE_APPROVAL" || !slices.Contains(held.Reasons, "MERGES_NEED_AN_INDEPENDENT_REVIEW") {
		t.Fatalf("REST merge: %d %+v", code, held)
	}
	slices.Sort(mcpReasons)
	if mcpDecision != held.Decision || !slices.Equal(mcpReasons, slices.Sorted(slices.Values(held.Reasons))) {
		t.Fatalf("MCP %s %v, REST %s %v", mcpDecision, mcpReasons, held.Decision, held.Reasons)
	}
	var now struct {
		Merged bool `json:"merged"`
	}
	d.do(t, http.MethodGet, "/repos/"+live.repo+"/pulls/"+strconv.Itoa(pr.Number), "", http.StatusOK, &now)
	if now.Merged {
		t.Fatal("merged while held")
	}
	t.Logf("held for %v; pull request #%d is closed and %s deleted at the end", held.Reasons, pr.Number, branch)
}
