// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && github_live && sandbox

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
	"github.com/katocxl/pantherclaw/internal/server"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The v0.1.0 preview's live GitHub run (task test:github-live, docs/runbooks/
// github-live.md): the three routes and the coding-to-production scenario
// (§43) against the founder's sandbox repository. Manual and opt-in, like
// m8_github_live_test.go, whose liveGitHub and direct it uses. Every object
// it makes is named pv-<nonce>; nothing is merged into the default branch.

// liveTimeout bounds each wait for GitHub or the gateway's verifier.
const liveTimeout = 10 * time.Minute

// liveNonce is the run's name: every branch and pull request carries it.
func liveNonce() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// livePlanted is a secret made for this run, never a real one: prefix and n
// lower-case letters and digits.
func livePlanted(prefix string, n int) string {
	s := strings.ToLower(rand.Text() + rand.Text() + rand.Text() + rand.Text())
	return prefix + s[:n]
}

// liveBranchHead is the default branch of the sandbox repository and its head.
func liveBranchHead(t *testing.T, d *direct, repo string) (string, string) {
	t.Helper()
	var info struct {
		DefaultBranch string `json:"default_branch"`
	}
	d.do(t, http.MethodGet, "/repos/"+repo, "", http.StatusOK, &info)
	return info.DefaultBranch, liveRef(t, d, repo, info.DefaultBranch)
}

func liveRef(t *testing.T, d *direct, repo, branch string) string {
	t.Helper()
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	d.do(t, http.MethodGet, "/repos/"+repo+"/git/ref/heads/"+branch, "", http.StatusOK, &ref)
	return ref.Object.SHA
}

// liveHeads is every branch of the repository and its head.
func liveHeads(t *testing.T, d *direct, repo string) map[string]string {
	t.Helper()
	var refs []struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	d.do(t, http.MethodGet, "/repos/"+repo+"/git/matching-refs/heads/?per_page=100", "", http.StatusOK, &refs)
	out := map[string]string{}
	for _, r := range refs {
		out[r.Ref] = r.Object.SHA
	}
	return out
}

// liveCreateBranch makes branch at sha, past PantherClaw, and deletes it
// when the test ends.
func liveCreateBranch(t *testing.T, d *direct, repo, branch, sha string) {
	t.Helper()
	d.do(t, http.MethodPost, "/repos/"+repo+"/git/refs", `{"ref":"refs/heads/`+branch+`","sha":"`+sha+`"}`, http.StatusCreated, nil)
	liveDeleteLater(t, d, repo, branch)
}

// liveDeleteLater deletes branch when the test ends; one that was never
// made is clean.
func liveDeleteLater(t *testing.T, d *direct, repo, branch string) {
	t.Helper()
	t.Cleanup(func() {
		err := d.call(http.MethodDelete, "/repos/"+repo+"/git/refs/heads/"+branch, "", http.StatusNoContent, nil)
		if err != nil && !strings.Contains(err.Error(), ": 422 ") && !strings.Contains(err.Error(), ": 404 ") {
			t.Logf("delete the branch %s by hand: %v", branch, err)
		}
	})
}

// liveClosePRLater closes pull request number when the test ends.
func liveClosePRLater(t *testing.T, d *direct, repo string, number int) {
	t.Helper()
	t.Cleanup(func() {
		if err := d.call(http.MethodPatch, "/repos/"+repo+"/pulls/"+strconv.Itoa(number), `{"state":"closed"}`, http.StatusOK, nil); err != nil {
			t.Logf("close pull request #%d by hand: %v", number, err)
		}
	})
}

func liveMerged(t *testing.T, d *direct, repo string, number int) bool {
	t.Helper()
	var pr struct {
		Merged bool `json:"merged"`
	}
	d.do(t, http.MethodGet, "/repos/"+repo+"/pulls/"+strconv.Itoa(number), "", http.StatusOK, &pr)
	return pr.Merged
}

// liveWait polls sql until it returns want, calling nudge (if any) each
// round, for liveTimeout.
func liveWait(t *testing.T, s *stack, want, sql string, nudge func(), args ...any) {
	t.Helper()
	got := ""
	for deadline := time.Now().Add(liveTimeout); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		if nudge != nil {
			nudge()
		}
		if got = s.row(t, sql, args...); got == want {
			return
		}
	}
	t.Fatalf("%s: %q after %s, want %q", sql, got, liveTimeout, want)
}

// liveStartSandbox is startM9 for the sandbox repository: the same stack,
// person, grant and mapped api.github.com, with GitHub itself behind the
// connection and a workspace that holds a PAT and an SSH key made for this
// run. It returns them.
func liveStartSandbox(t *testing.T, live *githubSim) (*m9, string, string) {
	t.Helper()
	c, e := dockertest.Client(t)
	m := &m9{
		agentImage: dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/test/e2e/testdata/liveagent", "test/e2e/testdata/liveagent.Dockerfile"),
		edgeImage:  dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile"),
		probe:      dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-probe", "deploy/sandbox/probe.Dockerfile"),
	}
	p := inProcessIdP(t)
	m.stack = start(t, options{budget: "1000.00", people: &p, github: true, githubAt: live, claimTimeout: time.Second})
	people := &m2Stack{url: m.apiURL, cfg: m.serverCfg, idp: p}
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", m.serverCfg, "--org", m.org.String()}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	m.alice = people.user(t, "alice", "alice@example.test")
	m.alice.login(t, m.org.String(), pciToken.FindStringSubmatch(out.String())[1])
	m.query(t, "SELECT agent_id::text, id::text FROM pc.grants ORDER BY created_at LIMIT 1", nil, &m.agent, &m.grant)
	alice := m.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'")
	for _, role := range []td.RoleName{td.RoleGatewayAdmin, td.RoleAgentOwner, td.RoleAgentAdmitter, td.RoleSecurityAdmin, td.RoleGrantIssuer} {
		if code, out, errs := m.alice.pclaw(t, "role", "bind", "--role", string(role), "--user", alice); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, out, errs)
		}
	}
	m.db.AdminExec(t, "UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1", m.org)
	m.db.AdminExec(t, "UPDATE pc.agents SET owner_user_id = $3 WHERE org_id = $1 AND id = $2", m.org, mustUUID(t, m.agent), mustUUID(t, alice))
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bounds := write("bounds.json", `{"operations": ["github.contents.read", "github.contents.write", "github.branch.create",
	  "github.pull.read", "github.pull.create", "github.pull.merge", "github.deployment.trigger"]}`)
	reqs := write("requirements.json", `[
	  {"operations": ["github.pull.merge"], "reason": "MERGES_NEED_AN_INDEPENDENT_REVIEW",
	   "approval": {"role": "code_reviewer", "count": 1, "independent": true}},
	  {"operations": ["github.deployment.trigger"], "reason": "DEPLOYMENTS_NEED_A_RELEASE",
	   "approval": {"role": "release_approver", "count": 1}}]`)
	code, out2, errs := m.alice.pclaw(t, "grant", "issue", m.agent, "--principal", "user:"+alice, "--expires", "24h",
		"--bounds-file", bounds, "--requirements-file", reqs, "--task", "preview live run")
	g := grantID.FindStringSubmatch(out2)
	if code != 0 || g == nil {
		t.Fatalf("grant issue: %d %s %s", code, out2, errs)
	}
	m.grant = g[1]
	m.mapAgentHost(t, "api.github.com")

	// The workspace a developer hands the agent: a PAT in its .env and an
	// SSH key, both made for this run.
	pat := livePlanted("ghp_", 36)
	armor := "OPENSSH " + "PRIVATE " + "KEY" // not spelled out, so that no scanner takes the source for a key
	key := "-----BEGIN " + armor + "-----\n" + base64.StdEncoding.EncodeToString([]byte(livePlanted("", 90))) + "\n-----END " + armor + "-----\n"
	m.workspace = t.TempDir()
	if err := os.MkdirAll(filepath.Join(m.workspace, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.workspace, ".env"), []byte("GITHUB_TOKEN="+pat+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.workspace, ".ssh", "id_ed25519"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	return m, pat, key
}

// liveCoverage reassesses the connection and returns the records of the
// agent's scopes as `pclaw coverage list` prints them, by operation.
func liveCoverage(t *testing.T, m *m9) map[string]card {
	t.Helper()
	if code, out, errs := m.alice.pclaw(t, "coverage", "reassess", m.gh.conn.String(), "--agent", m.agent); code != 0 {
		t.Fatalf("coverage reassess: %d %s %s", code, out, errs)
	}
	code, out, errs := m.alice.pclaw(t, "coverage", "list", "--agent", m.agent, "--connection", m.gh.conn.String())
	var list struct {
		Records []struct {
			Scope struct {
				Operation string `json:"operation"`
			} `json:"scope"`
			State      string `json:"state"`
			ExpireTime string `json:"expireTime"`
		} `json:"records"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &list, json.RejectUnknownMembers(false)) != nil {
		t.Fatalf("coverage list: %d %s %s", code, out, errs)
	}
	got := map[string]card{}
	for _, r := range list.Records {
		var c card
		c.Record.State, c.Record.ExpireTime = r.State, r.ExpireTime
		got[r.Scope.Operation] = c
	}
	return got
}

// TestLive_GitHub_ThreeRoutes: from inside one `pclaw sandbox run` session
// against the sandbox repository, the agent sets up through the edge (read,
// branch, write, open a pull request: all allowed); its raw merge to
// api.github.com is held exactly as the GitHub MCP server's is; a push with
// a planted PAT over HTTPS or a planted SSH key reaches nothing; the held
// attempts verify offline; and the coverage of the scopes it used reads
// ENFORCED for a day at most. Nothing is merged.
func TestLive_GitHub_ThreeRoutes(t *testing.T) {
	live := liveGitHub(t)
	d := newDirect(t, live)
	nonce := liveNonce()
	_, mainSHA := liveBranchHead(t, d, live.repo)
	// A throwaway base, so that nothing can land on the default branch.
	base, baseSHA := "pv-base-"+nonce, mainSHA
	liveCreateBranch(t, d, live.repo, base, mainSHA)
	before := liveHeads(t, d, live.repo)
	branch := "pv-" + nonce
	liveDeleteLater(t, d, live.repo, branch)
	m, pat, key := liveStartSandbox(t, live)

	// 0. Session 1: the agent sets up through the edge.
	code, out, errs := m.sandbox(t, pclaw.Options{}, "setup", live.repo, nonce, base, baseSHA)
	if code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox run 1: %d\n%s\n%s", code, out, errs)
	}
	for prefix, want := range map[string]string{"read ": "read 200", "branch ": "branch 201", "write ": "write 201"} {
		if got := lineOf(out, prefix); got != want {
			t.Fatalf("setup through the edge: %q, want %q\n%s", got, want, out)
		}
	}
	var number int
	var head string
	if _, err := fmt.Sscanf(lineOf(out, "pr "), "pr 201 %d %s", &number, &head); err != nil || number == 0 || head == "" {
		t.Fatalf("the pull request: %q\n%s", lineOf(out, "pr "), out)
	}
	liveClosePRLater(t, d, live.repo, number)

	// 1. The MCP merge, host-side as the agent's workload (the gateway's MCP
	// face is not reachable from the sandbox): held.
	mcp := m.ghMergeMCP(t, number, head)
	var mcpClass, mcpDecision, mcpTxn string
	var mcpReasons []string
	member(t, mcp, "error_class", &mcpClass)
	member(t, mcp, "decision", &mcpDecision)
	member(t, mcp, "reasons", &mcpReasons)
	member(t, mcp, "transaction_id", &mcpTxn)
	if mcpClass != "held" || mcpDecision != "REQUIRE_APPROVAL" || !slices.Contains(mcpReasons, "MERGES_NEED_AN_INDEPENDENT_REVIEW") {
		t.Fatalf("MCP merge: %s %s %v", mcpClass, mcpDecision, mcpReasons)
	}

	// 2 and 3. Session 2, once the agent's only instance is the sandbox's:
	// the raw merge of the same pull request, then the push attempts.
	m.revokeSeeded(t)
	code, out, errs = m.sandbox(t, pclaw.Options{}, "attack", live.repo, strconv.Itoa(number), head)
	mm := closurePassed.FindStringSubmatch(out)
	if code != 0 || mm == nil {
		t.Fatalf("sandbox run 2: %d\n%s\n%s", code, out, errs)
	}
	var curl reply
	line := lineOf(out, "merge ")
	if !strings.HasPrefix(line, "merge 403 ") || json.Unmarshal([]byte(strings.TrimPrefix(line, "merge 403 ")), &curl) != nil {
		t.Fatalf("the agent's raw merge: %q", line)
	}
	if curl.Decision != "REQUIRE_APPROVAL" || !slices.Contains(curl.Reasons, "MERGES_NEED_AN_INDEPENDENT_REVIEW") {
		t.Fatalf("raw merge: %+v", curl)
	}
	if curl.ErrorClass != mcpClass || curl.Decision != mcpDecision || !sameSet(curl.Reasons, mcpReasons) {
		t.Fatalf("raw %s %s %v, MCP %s %s %v", curl.ErrorClass, curl.Decision, curl.Reasons, mcpClass, mcpDecision, mcpReasons)
	}
	raw, viaMCP := m.heldAction(t, curl.TransactionID), m.heldAction(t, mcpTxn)
	if raw.Channel != "http" || viaMCP.Channel != "mcp" {
		t.Fatalf("channels %s and %s", raw.Channel, viaMCP.Channel)
	}
	if a, b := normalized(t, raw, viaMCP), normalized(t, viaMCP, viaMCP); a != b {
		t.Fatalf("the raw merge is another action:\n%s\n%s", a, b)
	}
	if raw.DedupeKey == "" || raw.DedupeKey != viaMCP.DedupeKey {
		t.Fatalf("dedupe keys %q and %q", raw.DedupeKey, viaMCP.DedupeKey)
	}
	if a, b := m.heldBinding(t, curl.TransactionID), m.heldBinding(t, mcpTxn); a != b {
		t.Fatalf("the holds differ:\nraw %+v\nMCP %+v", a, b)
	}
	if liveMerged(t, d, live.repo, number) {
		t.Fatal("merged while held")
	}

	// 3. The push with the planted credentials reached nothing.
	if l := lineOf(out, "https-push "); !strings.HasPrefix(l, "https-push error") && !strings.HasPrefix(l, "https-push 403") {
		t.Fatalf("git push over HTTPS: %q", l)
	}
	if l := lineOf(out, "ssh-key "); l != "ssh-key true" {
		t.Fatalf("the agent did not find the planted SSH key: %q", l)
	}
	for _, addr := range []string{"github.com:22", "140.82.112.3:22"} {
		if l := lineOf(out, "ssh "+addr); l != "ssh "+addr+" blocked" {
			t.Fatalf("git push over SSH: %q", l)
		}
	}
	after := liveHeads(t, d, live.repo)
	for ref, sha := range after {
		if ref == "refs/heads/"+branch {
			if sha != head {
				t.Fatalf("%s is %s, the pull request's head %s", ref, sha, head)
			}
			continue
		}
		if before[ref] != sha {
			t.Fatalf("%s moved from %q to %s", ref, before[ref], sha)
		}
	}
	for ref := range before {
		if _, ok := after[ref]; !ok {
			t.Fatalf("%s disappeared", ref)
		}
	}
	if logs := m.logs.String(); strings.Contains(logs, pat) || strings.Contains(logs, key[40:80]) {
		t.Fatal("a planted secret reached the server's logs")
	}

	// 4. The held attempts verify offline.
	p := m.proof(t)
	txns := []ids.UUID{mustUUID(t, curl.TransactionID), mustUUID(t, mcpTxn)}
	p.checkpointed(t, txns...)
	auditor := m.person(t, "live-auditor", td.RoleAuditor).ctx
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		file, _ := p.export(t, auditor, "live-held.json", evapp.Selection{Transactions: txns}, 0)
		code, r := p.verify(t, file)
		if code == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pclaw verify exit %d\n%+v", code, r.Checks)
		}
		if _, err := p.jobs.Insert(context.Background(), checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
	}

	// 4b. The closure of session 2, with the push probes (the planted-PAT and
	// SSH pushes), verifies offline: every check passed.
	closure := mustUUID(t, mm[1])
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		file, _ := p.export(t, auditor, "live-closure.json", evapp.Selection{Closures: []ids.UUID{closure}}, 0)
		code, r := p.verify(t, file)
		pushes := 0
		for _, c := range r.Checks {
			if c.Name == "closure.probe" && (strings.Contains(c.Subject, "ssh_push") || strings.Contains(c.Subject, "pat_push")) && c.Status == bundle.Passed {
				pushes++
			}
		}
		if code == 0 && pushes >= 2 && all(r, "closure.reports", bundle.Passed) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pclaw verify of closure %s: exit %d, %d push probes passed\n%+v", closure, code, pushes, r.Checks)
		}
		if _, err := p.jobs.Insert(context.Background(), checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
	}

	// 5. Coverage reads ENFORCED, for a day at most, for the scopes it used.
	scopes := []string{"github.contents.read", "github.branch.create", "github.contents.write", "github.pull.create", "github.pull.merge"}
	var got map[string]card
	for deadline := time.Now().Add(liveTimeout); ; time.Sleep(5 * time.Second) {
		got = liveCoverage(t, m)
		ok := true
		for _, op := range scopes {
			ok = ok && got[op].Record.State == enforced
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("coverage never read ENFORCED for every scope: %+v", got)
		}
	}
	for _, op := range scopes {
		until, err := time.Parse(time.RFC3339, got[op].Record.ExpireTime)
		if err != nil || until.Before(time.Now()) || until.After(time.Now().Add(24*time.Hour+time.Minute)) {
			t.Fatalf("%s is ENFORCED until %q: %v", op, got[op].Record.ExpireTime, err)
		}
	}
	t.Logf("three routes: pull request #%d held for %v over MCP and raw (%s); push with the planted PAT and SSH key reached nothing; bundle verified offline; coverage ENFORCED until %s",
		number, curl.Reasons, curl.Decision, mm[2])
}

// TestLive_GitHub_CodingToProduction is §43 against the sandbox repository:
// the merge is held, an independent code reviewer approves with a security
// key, the merge runs through the gateway's REST face into a throwaway base
// branch pv-base-<nonce> (never the default branch) and its effect is
// CONFIRMED against the branch head; the deployment it triggers is released
// by a release approver inside an open change window, the repository's
// deploy workflow reports success, and that effect is CONFIRMED too.
func TestLive_GitHub_CodingToProduction(t *testing.T) {
	live := liveGitHub(t)
	d := newDirect(t, live)
	nonce := liveNonce()
	main, mainSHA := liveBranchHead(t, d, live.repo)
	baseBranch, branch := "pv-base-"+nonce, "pv-"+nonce
	liveCreateBranch(t, d, live.repo, baseBranch, mainSHA)

	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, github: true, githubAt: live})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", s.serverCfg, "--org", s.org.String()}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, s.org.String(), pciToken.FindStringSubmatch(out.String())[1])
	_, carolB, carolKey, carol := s.reviewer(t, people, alice, "carol", td.RoleName("code_reviewer"))
	_, rachelB, rachelKey, rachel := s.reviewer(t, people, alice, "rachel", td.RoleName("release_approver"))
	// The gateway admin who sealed the App has a stand-in key, not a real
	// one; it is removed, so the export holds the reviewers' keys only.
	s.db.AdminExec(t, `UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()
		WHERE org_id = $1 AND name = 'key'`, s.org)
	if code, out, errs := alice.pclaw(t, "approver-keys", "export", "--out", s.approverKeys); code != 0 || !strings.Contains(out, "2 key(s)") {
		t.Fatalf("approver-keys export: %d %s %s", code, out, errs)
	}
	s.linkGitHub(t, carol, "carol-pv-"+nonce)
	s.linkGitHub(t, rachel, "rachel-pv-"+nonce)

	// 1. Reading, branching, writing and opening a pull request are allowed.
	api := "/repos/" + live.repo
	if code, r, _ := s.ghCall(t, http.MethodGet, api+"/contents/README.md?ref="+url.QueryEscape(baseBranch), "", ids.NewV7()); code != http.StatusOK {
		t.Fatalf("read: %d %+v", code, r)
	}
	if code, r, _ := s.ghCall(t, http.MethodPost, api+"/git/refs", `{"ref":"refs/heads/`+branch+`","sha":"`+mainSHA+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("branch: %d %+v", code, r)
	}
	liveDeleteLater(t, d, live.repo, branch)
	content := base64.StdEncoding.EncodeToString([]byte("written by task test:github-live " + nonce + "\n"))
	if code, r, _ := s.ghCall(t, http.MethodPut, api+"/contents/"+branch+".txt",
		`{"message":"PantherClaw live run `+nonce+`","content":"`+content+`","branch":"`+branch+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("write: %d %+v", code, r)
	}
	code, r, raw := s.ghCall(t, http.MethodPost, api+"/pulls", `{"title":"`+branch+`","head":"`+branch+`","base":"`+baseBranch+`"}`, ids.NewV7())
	var pr struct {
		Number int `json:"number"`
		Head   struct {
			SHA string `json:"sha"`
		} `json:"head"`
	}
	if code != http.StatusCreated || json.Unmarshal([]byte(raw), &pr) != nil || pr.Number == 0 {
		t.Fatalf("open: %d %+v %s", code, r, raw)
	}
	liveClosePRLater(t, d, live.repo, pr.Number)

	// 2. The merge is held for an independent code reviewer.
	act := ids.NewV7()
	code, held := s.ghMerge(t, act, pr.Number, pr.Head.SHA)
	if code != http.StatusForbidden || held.Decision != "REQUIRE_APPROVAL" || !slices.Contains(held.Reasons, "MERGES_NEED_AN_INDEPENDENT_REVIEW") || !slices.Contains(held.Reasons, "DEPLOYMENTS_NEED_A_RELEASE") {
		t.Fatalf("the merge: %d %+v", code, held)
	}
	if liveMerged(t, d, live.repo, pr.Number) {
		t.Fatal("merged while held")
	}

	// 3. The independent reviewer approves with a security key. The deploy
	// workflow runs on pushes to pv-base-*, so the merge may also wait for a
	// release approver, whose approval is usable inside an open change
	// window for production only.
	if code, state := s.approveMerge(t, carolB, carolKey, held.TransactionID); code != http.StatusOK {
		t.Fatalf("the code reviewer approves: %d %s", code, state)
	}
	merge := func() (int, reply, string) {
		return s.ghCall(t, http.MethodPut, api+"/pulls/"+strconv.Itoa(pr.Number)+"/merge", `{"sha":"`+pr.Head.SHA+`","merge_method":"squash"}`, act)
	}
	// Held for the release as well, until the approver approves.
	if code, r, raw = merge(); code == http.StatusOK || !slices.Contains(r.Reasons, "DEPLOYMENTS_NEED_A_RELEASE") {
		t.Fatalf("the merge after the review must wait for the release: %d %+v %s", code, r, raw)
	}
	s.exec(t, `INSERT INTO pc.change_windows (org_id, id, environment, time_zone, one_off, freezes, revision, created_by)
		VALUES ($1, $2, 'production', 'UTC', jsonb_build_array(jsonb_build_object('start', now() - interval '1 hour', 'end', now() + interval '1 hour')),
		'[]'::jsonb, 1, 'live')`, s.org, ids.NewV7())
	if code, state := s.approveMerge(t, rachelB, rachelKey, held.TransactionID); code != http.StatusOK || state != `"APPROVED"` {
		t.Fatalf("the release approver approves: %d %s", code, state)
	}
	code, r, raw = merge()
	if code != http.StatusOK || r.Outcome != "ACCEPTED" || r.TransactionID != held.TransactionID {
		t.Fatalf("the approved merge: %d %+v %s", code, r, raw)
	}
	var merged struct {
		SHA    string `json:"sha"`
		Merged bool   `json:"merged"`
	}
	if err := json.Unmarshal([]byte(raw), &merged); err != nil || !merged.Merged || merged.SHA == "" {
		t.Fatalf("GitHub's answer to the merge: %s: %v", raw, err)
	}

	// 4. The merge's effect is CONFIRMED, and the branch head, read back
	// through the gateway, is the merge commit.
	effectOf := "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1"
	liveWait(t, s, "CONFIRMED", effectOf, nil, held.TransactionID)
	code, r, raw = s.ghCall(t, http.MethodGet, api+"/git/ref/heads/"+baseBranch, "", ids.NewV7())
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(raw), &ref) != nil || ref.Object.SHA != merged.SHA {
		t.Fatalf("%s through the gateway: %d %+v %s, want the merge commit %s", baseBranch, code, r, raw, merged.SHA)
	}
	if liveRef(t, d, live.repo, main) != mainSHA {
		t.Fatalf("%s moved", main)
	}

	// 5. The deployment the merge triggered is verified on its own: pending
	// until the repository's deploy workflow reports success, then CONFIRMED.
	var consequence string
	for deadline := time.Now().Add(liveTimeout); consequence == ""; time.Sleep(2 * time.Second) {
		s.query(t, `SELECT coalesce((SELECT to_transaction_id::text FROM pc.transaction_links
			WHERE from_transaction_id = $1 AND kind = 'consequence'), '')`, []any{held.TransactionID}, &consequence)
		if consequence == "" && time.Now().After(deadline) {
			t.Fatal("no consequence transaction for the deployment")
		}
	}
	liveWait(t, s, "CONFIRMED", effectOf, func() {
		s.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", mustUUID(t, consequence))
	}, consequence)
	t.Logf("coding to production: pull request #%d merged into %s at %s, effect CONFIRMED; deployment CONFIRMED (consequence %s)",
		pr.Number, baseBranch, merged.SHA, consequence)
}
