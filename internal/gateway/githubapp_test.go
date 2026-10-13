// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

// gitHubWorld is the GitHub simulator with one App installed on acme for
// acme/payments, a branch fix/a and pull request 1 from it into main.
type gitHubWorld struct {
	sim  *github.Server
	url  string
	key  *rsa.PrivateKey
	head string
}

func newGitHubWorld(t *testing.T) *gitHubWorld {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sim := github.New(slog.New(slog.DiscardHandler))
	sim.RegisterApp(42, "Iv23liGateway", &key.PublicKey)
	sim.Install(github.Installation{ID: 7, Account: "acme", Repos: []string{"payments"}, Permissions: map[string]string{
		"contents": "write", "pull_requests": "write", "metadata": "read",
	}})
	sim.CreateRepo("acme/payments", "main", map[string]string{"README.md": "# payments\n"})
	head := sim.Push("acme/payments", "fix/a", map[string]string{"parser.go": "package parser\n"})
	sim.AddToken("ghp_setup", "alice", []string{"acme/payments"}, map[string]string{"pull_requests": "write"})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/repos/acme/payments/pulls",
		strings.NewReader(`{"title":"Fix","head":"fix/a","base":"main"}`))
	req.Header.Set("Authorization", "token ghp_setup")
	res, err := srv.Client().Do(req)
	if err != nil || res.StatusCode != http.StatusCreated {
		t.Fatalf("open the pull request: %v %v", res, err)
	}
	_ = res.Body.Close()
	return &gitHubWorld{sim: sim, url: srv.URL, key: key, head: head}
}

// withGitHubApp makes the connection a pc.github connection to the
// simulator, holding the App's key as a sealed GitHub App credential.
func withGitHubApp(t *testing.T, w *gitHubWorld) func(*harness) {
	return func(h *harness) {
		dir := t.TempDir()
		kek := filepath.Join(dir, "kek")
		if err := keys.GenerateKEKFile(kek); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "broker.json")
		if _, err := broker.Generate(t.Context(), path, []string{kek}); err != nil {
			t.Fatal(err)
		}
		key, err := broker.Load(t.Context(), path, []string{kek})
		if err != nil {
			t.Fatal(err)
		}
		h.broker = NewBroker(key, nil, nil)
		h.broker.id = "bk-1"
		pub, _ := pccrypto.ParseSealPublicKey(key.PublicKey())
		hosts := []string{"127.0.0.1"}
		bind := domain.Binding{
			Org: testOrg, Connection: connID, Version: 1, AllowedHosts: hosts, BrokerKey: "bk-1", Header: "Authorization", Scheme: "Bearer",
			Kind: domain.KindGitHubApp,
		}
		plain, err := domain.GitHubApp{
			V: 1, Issuer: "Iv23liGateway", Installation: 7, Account: "acme",
			PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(w.key)}),
		}.Encode()
		if err != nil {
			t.Fatal(err)
		}
		blob, err := pccrypto.Seal(pub, bind.Info(), domain.AAD, plain)
		if err != nil {
			t.Fatal(err)
		}
		h.pkgFile, h.targetURL = "../../packages/pc-github/package.yaml", w.url
		h.conn.GatewayConnection.Package, h.conn.AccessMode = "pc.github", "pantherclaw_held"
		h.conn.Credential = &pb.SealedCredential{
			Id: ids.NewV7().String(), ConnectionId: connID, Version: 1, BrokerKeyId: "bk-1", Sealed: blob, AllowedHosts: hosts,
			Header: "Authorization", Scheme: "Bearer", Kind: domain.KindGitHubApp,
		}
	}
}

// TestHR203_TheGatewayMintsATokenPerActionAndRevokesIt: each authorized
// action gets its own installation token for exactly its repository and its
// operation's permissions, placed for the dispatch and revoked after it;
// the agent never sees it, and the next action mints another.
func TestHR203_TheGatewayMintsATokenPerActionAndRevokesIt(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"encoding":"base64"`) {
		t.Fatalf("read = %d %s %+v", r.code, r.body, r.refusal)
	}
	r = h.do(t, http.MethodPut, "/payments/repos/acme/payments/pulls/1/merge", `{"sha":"`+w.head+`"}`, nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"merged":true`) {
		t.Fatalf("merge = %d %s %+v", r.code, r.body, r.refusal)
	}
	tokens := w.sim.Tokens()
	if len(tokens) != 2 {
		t.Fatalf("%d tokens minted, want one per action", len(tokens))
	}
	// Each token has exactly the operation's declared permissions, with the
	// metadata: read GitHub adds to every token.
	want := []map[string]string{{"contents": "read", "metadata": "read"}, {"contents": "write", "metadata": "read"}}
	for _, tok := range tokens {
		if !tok.Revoked || !slices.Equal(tok.Repos, []string{"acme/payments"}) || tok.Uses != 1 { // the action; the revocation is not a use
			t.Errorf("token %+v", tok)
		}
		if !slices.ContainsFunc(want, func(p map[string]string) bool { return maps.Equal(p, tok.Permissions) }) {
			t.Errorf("permissions %v", tok.Permissions)
		}
	}
	var merge github.Request
	for _, req := range w.sim.Requests() {
		if strings.Contains(req.Token, "ghs_") || strings.Contains(r.body, "ghs_") {
			t.Fatal("a token value was recorded or returned")
		}
		if req.Method == http.MethodPut {
			merge = req
		}
	}
	if merge.Status != http.StatusOK || merge.Installation != 7 || !maps.Equal(merge.Permissions, map[string]string{"contents": "write", "metadata": "read"}) {
		t.Fatalf("the merge went out with %+v", merge)
	}
	if recs := h.auth.snap().records; len(recs) != 2 || recs[0].GetOutcome() != pb.Outcome_OUTCOME_ACCEPTED || recs[1].GetOutcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("recorded %v", recs)
	}
}

// TestHR203_NoTokenNoDispatch: an operation outside the App's installed
// permissions, or a repository on another account, gets no token, and
// nothing is sent to it.
func TestHR203_NoTokenNoDispatch(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	for name, c := range map[string]struct{ method, path, body string }{
		"a permission the App lacks": {http.MethodPatch, "/payments/repos/acme/payments", `{"delete_branch_on_merge":true}`},
		"another account":            {http.MethodGet, "/payments/repos/evil/payments/contents/README.md", ""},
	} {
		r := h.do(t, c.method, c.path, c.body, nil)
		if r.code != http.StatusBadGateway || r.refusal.Error != "credential_unavailable" {
			t.Errorf("%s: %d %+v", name, r.code, r.refusal)
		}
	}
	for _, req := range w.sim.Requests() {
		if req.User == "alice" {
			continue // the test's own setup
		}
		if req.Method != http.MethodPost || !strings.HasSuffix(req.Path, "/access_tokens") {
			t.Fatalf("something besides a token request reached GitHub: %+v", req)
		}
	}
	if got := w.sim.Tokens(); len(got) != 0 {
		t.Fatalf("minted %+v", got)
	}
}
