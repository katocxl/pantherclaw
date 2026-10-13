// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
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

	"google.golang.org/protobuf/proto"

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
		"contents": "write", "pull_requests": "write", "metadata": "read", "checks": "read",
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
		// The installation the server recorded with the seal (G3c).
		h.conn.Github = &pb.GitHubInstallation{AppClientId: "Iv23liGateway", InstallationId: 7, AccountLogin: "acme"}
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
// permissions gets no token, a repository on another account is refused
// before that (WRONG_ACCOUNT), and nothing is sent to either.
func TestHR203_NoTokenNoDispatch(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	for name, c := range map[string]struct {
		method, path, body string
		code               int
		want               string
	}{
		"a permission the App lacks": {http.MethodPatch, "/payments/repos/acme/payments", `{"delete_branch_on_merge":true}`, http.StatusBadGateway, "credential_unavailable"},
		"another account":            {http.MethodGet, "/payments/repos/evil/payments/contents/README.md", "", http.StatusForbidden, "WRONG_ACCOUNT"},
	} {
		r := h.do(t, c.method, c.path, c.body, nil)
		if r.code != c.code || r.refusal.Error != c.want {
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

// withInstallation records the connection's GitHub App installation, as
// the server's configuration carries it (connection_github).
func withInstallation(app string, installation int64, account string) func(*harness) {
	return func(h *harness) {
		h.conn.Github = &pb.GitHubInstallation{AppClientId: app, InstallationId: installation, AccountLogin: account}
	}
}

// TestHR203_AnotherAccountIsRefusedBeforeTheDecision: with the connection's
// installation recorded, an action on another account's repository is
// CANNOT_AUTHORIZE WRONG_ACCOUNT before the Authority is asked or GitHub
// reached; the installation's own repositories go ahead as before.
func TestHR203_AnotherAccountIsRefusedBeforeTheDecision(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w), withInstallation("Iv23liGateway", 7, "acme"))
	r := h.do(t, http.MethodGet, "/payments/repos/evil/payments/contents/README.md", "", nil)
	if r.code != http.StatusForbidden || r.refusal.Error != "WRONG_ACCOUNT" || r.refusal.Decision != "CANNOT_AUTHORIZE" {
		t.Fatalf("another account: %d %+v", r.code, r.refusal)
	}
	if n := h.auth.snap().authorize; n != 0 || len(w.sim.Requests()) != 1 { // the test's own pull request
		t.Fatalf("%d decisions, %d GitHub requests: another account went further than the gateway", n, len(w.sim.Requests()))
	}
	if r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil); r.code != http.StatusOK {
		t.Fatalf("the installation's own repository: %d %+v", r.code, r.refusal)
	}
}

// TestHR203_ASealForAnotherInstallationMintsNothing: a GitHub App
// credential whose sealed installation is not the one the connection
// records mints no token, so nothing is sent.
func TestHR203_ASealForAnotherInstallationMintsNothing(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w), withInstallation("Iv23liGateway", 8, "acme"))
	r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil)
	if r.code != http.StatusBadGateway || r.refusal.Error != "credential_unavailable" {
		t.Fatalf("a seal for installation 7 on a connection of installation 8: %d %+v", r.code, r.refusal)
	}
	if got := w.sim.Tokens(); len(got) != 0 {
		t.Fatalf("minted %+v", got)
	}
}

// TestHR203_TheExecutionRecordCarriesTheAccessNotTheToken: the gateway
// reports what the action's token allowed with its outcome, after it was
// revoked, for the execution receipt (ADR-0021 item 5), and never the token.
func TestHR203_TheExecutionRecordCarriesTheAccessNotTheToken(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	if r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil); r.code != http.StatusOK {
		t.Fatalf("read = %d %+v", r.code, r.refusal)
	}
	recs := h.auth.snap().records
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	a, read := recs[0].GetCredentialAccess(), map[string]string{"contents": "read"}
	if a.GetInstallationId() != 7 || a.GetRepository() != "acme/payments" || a.GetRepositoryId() <= 0 || !maps.Equal(a.GetRequested(), read) ||
		!maps.Equal(a.GetGranted(), map[string]string{"contents": "read", "metadata": "read"}) || a.GetExpireTime() == nil || a.GetRevocation() != "revoked" {
		t.Fatalf("access %+v", a)
	}
	raw, err := proto.Marshal(recs[0])
	if err != nil || bytes.Contains(raw, []byte("ghs_")) {
		t.Fatalf("the record carries a token: %v", err)
	}
}

// TestHR203_AnAppWithoutARecordedInstallationIsRefused: a GitHub App
// connection whose installation is not recorded (a seal from before the
// server recorded it) is CANNOT_AUTHORIZE INSTALLATION_UNKNOWN before the
// Authority is asked or GitHub reached: the account it may act on is
// unknown.
func TestHR203_AnAppWithoutARecordedInstallationIsRefused(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w), func(h *harness) { h.conn.Github = nil })
	r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil)
	if r.code != http.StatusForbidden || r.refusal.Error != "INSTALLATION_UNKNOWN" || r.refusal.Decision != "CANNOT_AUTHORIZE" {
		t.Fatalf("no recorded installation: %d %+v", r.code, r.refusal)
	}
	if n := h.auth.snap().authorize; n != 0 || len(w.sim.Requests()) != 1 { // the test's own pull request
		t.Fatalf("%d decisions, %d GitHub requests", n, len(w.sim.Requests()))
	}
}

// TestHR203_AWiderGrantIsRefusedWithItsAccess: a token GitHub grants wider
// than the operation declares is revoked and nothing is sent
// (credential_scope_mismatch), and the refused dispatch's record says what
// GitHub granted and that it was revoked (ADR-0021 items 3, 5 and 6).
func TestHR203_AWiderGrantIsRefusedWithItsAccess(t *testing.T) {
	w := newGitHubWorld(t)
	h := setup(t, withGitHubApp(t, w))
	w.sim.SetFaults(github.Faults{WiderGrant: true})
	r := h.do(t, http.MethodGet, "/payments/repos/acme/payments/contents/README.md", "", nil)
	if r.refusal.Error != "credential_scope_mismatch" {
		t.Fatalf("a wider grant: %d %+v", r.code, r.refusal)
	}
	recs := h.auth.snap().records
	if len(recs) != 1 || recs[0].GetOutcome() != pb.Outcome_OUTCOME_FAILED {
		t.Fatalf("records %v", recs)
	}
	a := recs[0].GetCredentialAccess()
	if a == nil || a.GetRevocation() != "revoked" || !maps.Equal(a.GetRequested(), map[string]string{"contents": "read"}) ||
		a.GetGranted()["contents"] != "write" {
		t.Fatalf("access of the refused grant %+v", a)
	}
	for _, tok := range w.sim.Tokens() {
		if !tok.Revoked || tok.Uses != 0 {
			t.Fatalf("token %+v", tok)
		}
	}
}
