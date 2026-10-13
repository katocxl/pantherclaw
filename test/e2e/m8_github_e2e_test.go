// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/server"
	"github.com/katocxl/pantherclaw/internal/sim/github"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The coding-to-production scenario of G0 M8 (§43), end to end on the
// GitHub simulator: an agent with a GitHub App connection held by the
// gateway reads, branches, writes and opens a pull request freely; its
// merge waits for an independent code reviewer whose GitHub account is
// linked by sign-in, and, because main deploys to production on push, for
// a release approver inside a change window; the approval is bound to the
// head commit; a task merges once.

// The GitHub App the simulator registers and installs on acme.
const (
	ghAppID        = "Iv23liE2E"
	ghInstallation = 7
	ghAccount      = "acme"
	ghRepo         = "acme/payments"
)

// deployOnMain deploys main to production on every push.
const deployOnMain = "name: deploy\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n" +
	"    environment: production\n    steps: [{run: make deploy}]\n"

// githubSim is the GitHub a stack's connection "github" calls
// (options.github): the simulator, or, for task test:github-live, GitHub
// itself, with sim nil. app, installation and account name its App; repo
// is the repository the agent works in.
type githubSim struct {
	sim          *github.Server
	url          string
	conn         ids.UUID
	key          *rsa.PrivateKey
	app, account string
	installation int64
	repo         string
}

// startGitHubSim starts the GitHub simulator: the App, installed on acme
// for acme/payments, whose main deploys to production on push.
func startGitHubSim(t *testing.T) *githubSim {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sim := github.New(slog.New(slog.DiscardHandler))
	sim.RegisterApp(42, ghAppID, &key.PublicKey)
	sim.Install(github.Installation{ID: ghInstallation, Account: ghAccount, Repos: []string{"payments"}, Permissions: map[string]string{
		"contents": "write", "pull_requests": "write", "metadata": "read", "checks": "read", "statuses": "read",
	}})
	sim.CreateRepo(ghRepo, "main", map[string]string{"README.md": "# payments\n", ".github/workflows/deploy.yml": deployOnMain})
	sim.DeployOnPush(ghRepo, "main", "production", time.Hour)
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	return &githubSim{sim: sim, url: srv.URL, key: key, app: ghAppID, installation: ghInstallation, account: ghAccount, repo: ghRepo}
}

// sealGitHubApp seals the App's key for the github connection, with its
// installation, as a gateway admin does with pclaw seal --github-app, and
// returns the gateway configuration version that carries it.
func (s *stack) sealGitHubApp(t *testing.T) int64 {
	t.Helper()
	admin := s.person(t, "github-admin", td.RoleGatewayAdmin)
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin.ctx, s.gh.conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(s.gh.key)})
	plain, err := creddomain.GitHubApp{V: 1, Issuer: s.gh.app, Installation: s.gh.installation, Account: s.gh.account, PrivateKey: pemKey}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b := k.Binding
	b.Kind = creddomain.KindGitHubApp
	sealed, err := pccrypto.Seal(pub, b.Info(), creddomain.AAD, plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin.ctx, credapp.PutInput{
		Connection: s.gh.conn, BrokerKey: mustUUID(t, b.BrokerKey), Version: b.Version, Sealed: sealed, AllowedHosts: b.AllowedHosts,
		Header: b.Header, Scheme: b.Scheme, Kind: creddomain.KindGitHubApp,
		GitHub: &creddomain.Installation{AppClientID: s.gh.app, ID: s.gh.installation, Account: s.gh.account},
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// ghCall sends one request through the github connection as the seeded
// workload, signed with PAP/1, and returns the status, the gateway's
// refusal or PC-* facts, and the body.
func (s *stack) ghCall(t *testing.T, method, path, body string, act ids.UUID) (int, reply, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, s.gateway+"/github"+path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, act.String())
	client := &http.Client{Timeout: 60 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var r reply
	if resp.StatusCode >= 300 {
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, raw)
		}
		return resp.StatusCode, r, string(raw)
	}
	r.TransactionID, r.Outcome, r.Receipt = resp.Header.Get("PC-Transaction-Id"), resp.Header.Get("PC-Outcome"), resp.Header.Get("PC-Receipt")
	return resp.StatusCode, r, string(raw)
}

// ghMerge asks to merge pull request number at sha over the REST face.
func (s *stack) ghMerge(t *testing.T, act ids.UUID, number int, sha string) (int, reply) {
	t.Helper()
	code, r, _ := s.ghCall(t, http.MethodPut, "/repos/"+s.gh.repo+"/pulls/"+strconv.Itoa(number)+"/merge",
		`{"sha":"`+sha+`","merge_method":"squash"}`, act)
	return code, r
}

// ghMergeMCP asks to merge over the MCP face (the GitHub MCP server's
// merge_pull_request tool) and returns PantherClaw's facts about the
// answer: io.pantherclaw/error for a tool error, nil when it ran.
func (s *stack) ghMergeMCP(t *testing.T, number int, sha string) map[string]jsontext.Value {
	t.Helper()
	owner, repo, _ := strings.Cut(s.gh.repo, "/")
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"merge_pull_request","arguments":{"owner":"` + owner + `",` +
		`"repo":"` + repo + `","pullNumber":` + strconv.Itoa(number) + `,"expectedHeadSha":"` + sha + `","merge_method":"squash"},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/mcp/github", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "merge_pull_request")
	req.Header.Set(gateway.HeaderRunID, s.run)
	client := &http.Client{Timeout: 60 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if i := bytes.Index(raw, []byte("data: ")); i >= 0 { // an event stream of one message
		raw = bytes.TrimSpace(raw[i+len("data: "):])
	}
	var out struct {
		Result struct {
			IsError bool                                 `json:"isError"`
			Meta    map[string]map[string]jsontext.Value `json:"_meta"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("MCP answer %d %s: %v", resp.StatusCode, raw, err)
	}
	if !out.Result.IsError {
		return nil
	}
	return out.Result.Meta["io.pantherclaw/error"]
}

// member reads a JSON string or string list from an MCP fact.
func member(t *testing.T, facts map[string]jsontext.Value, name string, v any) {
	t.Helper()
	if err := json.Unmarshal(facts[name], v); err != nil {
		t.Fatalf("%s in %v: %v", name, facts, err)
	}
}

// reviewer invites a person with role, signs them in, registers their
// security key and makes their account, role and key old enough to
// approve (the cooldowns, decision 5); it returns their command
// line, browser, key and user id.
func (s *stack) reviewer(t *testing.T, people *m2Stack, admin *user, name string, role td.RoleName) (*user, *browser, *webauthntest.Authenticator, ids.UUID) {
	t.Helper()
	org, email := s.org.String(), name+"@example.test"
	code, invite, errs := admin.pclaw(t, "invite", "create", "--email", email)
	if code != 0 || pciToken.FindStringSubmatch(invite) == nil {
		t.Fatalf("invite %s: %d %s %s", name, code, invite, errs)
	}
	u := people.user(t, name, email)
	u.login(t, org, pciToken.FindStringSubmatch(invite)[1])
	b := newBrowser(people)
	b.signIn(t, org, name, email, true)
	key, err := webauthntest.New(s.apiURL, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	code, body := b.post(t, "/account/keys/registration-options", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("registration options: %d %v", code, body)
	}
	resp, err := key.Register(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	if code, body = b.post(t, "/account/keys", map[string]any{"ceremony": body["ceremony"], "name": "Desk key", "response": jsontext.Value(resp)}); code != http.StatusOK {
		t.Fatalf("add key: %d %v", code, body)
	}
	for _, q := range []string{
		`UPDATE pc.users SET created_at = now() - interval '30 days' WHERE org_id = $1 AND subject = $2`,
		`UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1
			AND user_id = (SELECT id FROM pc.users WHERE org_id = $1 AND subject = $2)`,
		`UPDATE pc.webauthn_credentials SET created_at = now() - interval '30 days' WHERE org_id = $1
			AND user_id = (SELECT id FROM pc.users WHERE org_id = $1 AND subject = $2)`,
	} {
		s.db.AdminExec(t, q, s.org, name)
	}
	var id string
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = $1", []any{name}, &id)
	// The role is the team's: bound for the environment the agent works in.
	var env string
	s.query(t, "SELECT environment_id::text FROM pc.grants LIMIT 1", nil, &env)
	if code, _, errs := admin.pclaw(t, "role", "bind", "--role", string(role), "--user", id, "--scope", "env", "--scope-id", env); code != 0 {
		t.Fatalf("role bind %s: %d %s", name, code, errs)
	}
	s.db.AdminExec(t, `UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1 AND role = $2
		AND user_id = (SELECT id FROM pc.users WHERE org_id = $1 AND subject = $3)`, s.org, string(role), name)
	return u, b, key, mustUUID(t, id)
}

// linkGitHub links a person to the GitHub account login, as `pclaw github
// link` does once they proved it by signing in to GitHub (P2f, HR-207).
func (s *stack) linkGitHub(t *testing.T, user ids.UUID, login string) {
	t.Helper()
	gid := github.AccountID(login)
	s.db.AdminExec(t, `INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by, verified_at)
		VALUES ($1, $2, $3, $4, $5, 'e2e', now())`, s.org, ids.NewV7(), user, login, gid)
	s.db.AdminExec(t, `INSERT INTO pc.github_identity_history (org_id, github_user_id, user_id) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, s.org, gid, user)
}

// approveMerge has a person approve the latest request of txn on its page
// with their key; it returns the status of the step that answered, and
// the request's state or the refusal.
func (s *stack) approveMerge(t *testing.T, b *browser, key *webauthntest.Authenticator, txn string) (int, string) {
	t.Helper()
	path := "/approvals/" + s.requestOf(t, txn)
	if code, page := b.page(t, path+"?org="+s.org.String()); code != http.StatusOK || !strings.Contains(page, "github.pull.merge") {
		t.Fatalf("approval page: %d", code)
	}
	code, body := b.post(t, path+"/approve-options", map[string]any{})
	if code != http.StatusOK {
		raw, _ := json.Marshal(body)
		return code, string(raw)
	}
	resp, err := key.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	code, body = b.post(t, path+"/approve", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)})
	if code != http.StatusOK {
		raw, _ := json.Marshal(body)
		return code, string(raw)
	}
	return code, string(body["state"])
}

// TestE2E_M8_CodingToProduction is §43 end to end on the simulator.
func TestE2E_M8_CodingToProduction(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, github: true})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", s.serverCfg, "--org", s.org.String()}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, s.org.String(), pciToken.FindStringSubmatch(out.String())[1])
	carolCLI, carolB, carolKey, carol := s.reviewer(t, people, alice, "carol", td.RoleName("code_reviewer"))
	_, rachelB, rachelKey, rachel := s.reviewer(t, people, alice, "rachel", td.RoleName("release_approver"))
	// The gateway admin who sealed the App has a stand-in key, not a real
	// one; it is removed, so the export holds the reviewers' keys only.
	s.db.AdminExec(t, `UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()
		WHERE org_id = $1 AND name = 'key'`, s.org)
	if code, out, errs := alice.pclaw(t, "approver-keys", "export", "--out", s.approverKeys); code != 0 || !strings.Contains(out, "2 key(s)") {
		t.Fatalf("approver-keys export: %d %s %s", code, out, errs)
	}
	s.linkGitHub(t, carol, "carol-gh")
	s.linkGitHub(t, rachel, "rachel-gh")
	gh := s.gh.sim
	main := gh.Branch(ghRepo, "main")

	// 1. Reading, branching, writing and opening a pull request are allowed
	// and run with the App's per-action tokens.
	if code, r, _ := s.ghCall(t, http.MethodGet, "/repos/"+ghRepo+"/contents/README.md", "", ids.NewV7()); code != http.StatusOK {
		t.Fatalf("read: %d %+v", code, r)
	}
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/git/refs", `{"ref":"refs/heads/fix/cve","sha":"`+main+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("branch: %d %+v", code, r)
	}
	content := base64.StdEncoding.EncodeToString([]byte("package parser // fixed\n"))
	if code, r, _ := s.ghCall(t, http.MethodPut, "/repos/"+ghRepo+"/contents/src/parser.go",
		`{"message":"Fix the parser","content":"`+content+`","branch":"fix/cve"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("write: %d %+v", code, r)
	}
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/pulls", `{"title":"Fix the parser","head":"fix/cve","base":"main"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("open: %d %+v", code, r)
	}
	pr, _ := gh.PullRequest(ghRepo, 1)
	head := pr.HeadSHA

	// 2. The merge is held, the same over MCP and over REST: it needs an
	// independent code reviewer, and, since main deploys to production on
	// push, a release approver.
	mcp := s.ghMergeMCP(t, 1, head)
	var mcpClass, mcpDecision string
	var mcpReasons []string
	member(t, mcp, "error_class", &mcpClass)
	member(t, mcp, "decision", &mcpDecision)
	member(t, mcp, "reasons", &mcpReasons)
	act := ids.NewV7()
	code, held := s.ghMerge(t, act, 1, head)
	if code != http.StatusForbidden || held.ErrorClass != "held" || held.Decision != "REQUIRE_APPROVAL" {
		t.Fatalf("REST merge: %d %+v", code, held)
	}
	slices.Sort(mcpReasons)
	restReasons := slices.Sorted(slices.Values(held.Reasons))
	if mcpClass != held.ErrorClass || mcpDecision != held.Decision || !slices.Equal(mcpReasons, restReasons) {
		t.Fatalf("MCP %s %s %v, REST %s %s %v", mcpClass, mcpDecision, mcpReasons, held.ErrorClass, held.Decision, restReasons)
	}
	for _, want := range []string{"MERGES_NEED_AN_INDEPENDENT_REVIEW", "DEPLOYMENTS_NEED_A_RELEASE"} {
		if !slices.Contains(restReasons, want) {
			t.Fatalf("held for %v, want %s", restReasons, want)
		}
	}
	if p, _ := gh.PullRequest(ghRepo, 1); p.Merged {
		t.Fatal("merged while held")
	}

	// 3. Both approve with their security keys; outside a change window
	// for production the release approval cannot be used.
	if code, state := s.approveMerge(t, carolB, carolKey, held.TransactionID); code != http.StatusOK {
		t.Fatalf("carol approves: %d %s", code, state)
	}
	if code, state := s.approveMerge(t, rachelB, rachelKey, held.TransactionID); code != http.StatusOK || state != `"APPROVED"` {
		t.Fatalf("rachel approves: %d %s", code, state)
	}
	if code, r := s.ghMerge(t, act, 1, head); code == http.StatusOK || !strings.Contains(strings.Join(r.Reasons, " ")+r.Error, "CHANGE_WINDOW_CLOSED") {
		t.Fatalf("outside a change window: %d %+v", code, r)
	}

	// 4. A new commit voids the approval: the merge was bound to the head.
	gh.PushAs(ghRepo, "fix/cve", "dave", map[string]string{"src/extra.go": "package parser\n"})
	if code, r := s.ghMerge(t, act, 1, head); code == http.StatusOK {
		t.Fatalf("a merge at the old head: %d %+v", code, r)
	}
	if p, _ := gh.PullRequest(ghRepo, 1); p.Merged {
		t.Fatal("merged at a moved head")
	}
	pr, _ = gh.PullRequest(ghRepo, 1)
	head = pr.HeadSHA

	// 5. dave pushed and is linked to nobody: no one can approve until he
	// links his account.
	act = ids.NewV7()
	code, held = s.ghMerge(t, act, 1, head)
	if code != http.StatusForbidden || held.Decision != "REQUIRE_APPROVAL" {
		t.Fatalf("the merge at the new head: %d %+v", code, held)
	}
	if code, refusal := s.approveMerge(t, carolB, carolKey, held.TransactionID); code != http.StatusForbidden {
		t.Fatalf("an approval while an unlinked person pushed: %d %s", code, refusal)
	}
	if code, out, errs := carolCLI.pclaw(t, "approval", "get", s.requestOf(t, held.TransactionID)); code != 0 || !strings.Contains(out, "GITHUB_PEOPLE_NOT_LINKED") {
		t.Fatalf("why carol may not approve: %d %s %s", code, out, errs)
	}
	dave := s.person(t, "dave", td.RoleDeveloper)
	var daveID string
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'dave'", nil, &daveID)
	_ = dave
	s.linkGitHub(t, mustUUID(t, daveID), "dave")
	if code, state := s.approveMerge(t, carolB, carolKey, held.TransactionID); code != http.StatusOK {
		t.Fatalf("carol approves once dave is linked: %d %s", code, state)
	}
	if code, state := s.approveMerge(t, rachelB, rachelKey, held.TransactionID); code != http.StatusOK || state != `"APPROVED"` {
		t.Fatalf("rachel approves again: %d %s", code, state)
	}

	// 6. Inside a change window for production the merge runs once, at the
	// approved head; GitHub accepted it, and its effect is confirmed apart.
	s.exec(t, `INSERT INTO pc.change_windows (org_id, id, environment, time_zone, one_off, freezes, revision, created_by)
		VALUES ($1, $2, 'production', 'UTC', jsonb_build_array(jsonb_build_object('start', now() - interval '1 hour', 'end', now() + interval '1 hour')),
		'[]'::jsonb, 1, 'e2e')`, s.org, ids.NewV7())
	code, done := s.ghMerge(t, act, 1, head)
	if code != http.StatusOK || done.Outcome != "ACCEPTED" || done.TransactionID != held.TransactionID {
		t.Fatalf("the approved merge: %d %+v", code, done)
	}
	if p, _ := gh.PullRequest(ghRepo, 1); !p.Merged || p.HeadSHA != head {
		t.Fatalf("pull request %+v", p)
	}
	s.eventually(t, "CONFIRMED", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", done.TransactionID)
	for _, r := range gh.Requests() {
		if r.Method == http.MethodPut && strings.HasSuffix(r.Path, "/merge") && r.Status == http.StatusOK &&
			(!slices.Equal(r.Repos, []string{ghRepo}) || r.Installation != ghInstallation || r.Permissions["contents"] != "write" || len(r.Permissions) > 2) {
			t.Fatalf("the merge's token: %+v", r)
		}
	}
	if d := gh.Deployments(ghRepo); len(d) != 1 || d[0].Environment != "production" || d[0].SHA != gh.Branch(ghRepo, "main") {
		t.Fatalf("deployments after the merge: %+v", d)
	}

	// 7. The approval is consumed once: the same request again merges
	// nothing more, and the task's one merge is spent.
	merges := func() int {
		n := 0
		for _, r := range gh.Requests() {
			if r.Method == http.MethodPut && strings.HasSuffix(r.Path, "/merge") && r.Status == http.StatusOK {
				n++
			}
		}
		return n
	}
	if again, _ := s.ghMerge(t, act, 1, head); merges() != 1 {
		t.Fatalf("the same merge again: %d, %d merges", again, merges())
	}

	// 8. A pull request that changes a workflow: what merging deploys
	// cannot be read, so the consequence is unknown and the merge holds.
	gh.PushAs(ghRepo, "ci/x", "rachel-gh", map[string]string{".github/workflows/deploy.yml": deployOnMain + "# changed\n"})
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/pulls", `{"title":"CI","head":"ci/x","base":"main"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("open 2: %d %+v", code, r)
	}
	pr2, _ := gh.PullRequest(ghRepo, 2)
	code, unknown := s.ghMerge(t, ids.NewV7(), 2, pr2.HeadSHA)
	if code == http.StatusOK || !slices.Contains(unknown.Reasons, "CONSEQUENCE_UNKNOWN") {
		t.Fatalf("a merge whose deployment cannot be read: %d %+v", code, unknown)
	}
	if p, _ := gh.PullRequest(ghRepo, 2); p.Merged || merges() != 1 {
		t.Fatal("merged with an unknown consequence")
	}

	// 9. The task merges once: a clean pull request is refused, its one
	// merge spent.
	gh.PushAs(ghRepo, "fix/more", "rachel-gh", map[string]string{"src/more.go": "package parser\n"})
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/pulls", `{"title":"More","head":"fix/more","base":"main"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("open 3: %d %+v", code, r)
	}
	pr3, _ := gh.PullRequest(ghRepo, 3)
	code, spent := s.ghMerge(t, ids.NewV7(), 3, pr3.HeadSHA)
	if code == http.StatusOK || !strings.Contains(strings.Join(spent.Reasons, " ")+spent.Error, "BUDGET_EXHAUSTED") {
		t.Fatalf("a second merge in the task: %d %+v", code, spent)
	}
	if p, _ := gh.PullRequest(ghRepo, 3); p.Merged || merges() != 1 {
		t.Fatal("merged twice in one task")
	}

	// Every token the gateway minted, for actions and for fact reads, was
	// revoked after its use (HR-203).
	for _, tok := range gh.Tokens() {
		if tok.Installation == ghInstallation && !tok.Revoked {
			t.Fatalf("a token left valid: %+v", tok)
		}
	}
}
