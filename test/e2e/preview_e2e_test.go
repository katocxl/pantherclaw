// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && sandbox

package e2e

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"
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
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The v0.1.0 preview demo, "three routes, three stops", in one test: the
// real server, gateway and GitHub simulator, a real sandboxed agent
// (`pclaw sandbox run`, real Docker containers) on the "pc-github"
// connection, held by PantherClaw (pantherclaw_held, a GitHub App) in
// enforce mode, with the "coding to production" template applied.
//
//	0  setup traffic through the edge: all allowed
//	1  the MCP route: a merge without a reviewer is held
//	2  the raw route: curl to api.github.com is the same action, held alike
//	3  the credential route: a push with a planted PAT or SSH key fails
//	4  each attempt's evidence verifies offline
//	5  the coverage card reads ENFORCED, with expiry, for every operation used
//
// Two sandbox sessions, not one: the MCP route is the host-side MCP face by
// design (G0 M9, B6: curl from the sandbox against the MCP merge_pull_request
// call, identical except channel and per-call ids; docs/g0/M9.md:480), which
// the sandbox's edge, an HTTP proxy to the gateway's HTTP face, does not
// carry. So the harness makes the MCP merge as the agent's seeded workload,
// as TestE2E_M9_RawCurlSameDecision does, between the session that opens
// the pull request (step 0) and the session that attacks it (steps 2 and
// 3). Run by `task test:preview`.

// previewOps are the repository operations the flow uses.
var previewOps = []string{"github.contents.read", "github.branch.create", "github.contents.write", "github.pull.create", "github.pull.merge"}

// previewRecord is a coverage record as `pclaw coverage list` prints it.
type previewRecord struct {
	Scope struct {
		Operation string `json:"operation"`
	} `json:"scope"`
	State      string `json:"state"`
	ExpireTime string `json:"expireTime"`
	ClosureID  string `json:"closureId"`
}

// previewCoverage lists the agent's coverage records by operation, after a
// reassessment, as the server's periodic job makes it every minute.
func previewCoverage(t *testing.T, m *m9) map[string]previewRecord {
	t.Helper()
	if code, out, errs := m.alice.pclaw(t, "coverage", "reassess", m.gh.conn.String(), "--agent", m.agent); code != 0 {
		t.Fatalf("coverage reassess: %d %s %s", code, out, errs)
	}
	code, out, errs := m.alice.pclaw(t, "coverage", "list", "--agent", m.agent, "--connection", m.gh.conn.String())
	var list struct {
		Records []previewRecord `json:"records"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &list, json.RejectUnknownMembers(false)) != nil {
		t.Fatalf("coverage list: %d %s %s", code, out, errs)
	}
	by := map[string]previewRecord{}
	for _, r := range list.Records {
		by[r.Scope.Operation] = r
	}
	return by
}

// previewLineOK checks that the agent's line "name STATUS …" has a 2xx status.
func previewLineOK(t *testing.T, out, name string) {
	t.Helper()
	line := lineOf(out, name+" ")
	f := strings.Fields(line)
	if len(f) < 2 {
		t.Fatalf("the agent's %s: %q\n%s", name, line, out)
	}
	if n, err := strconv.Atoi(f[1]); err != nil || n < 200 || n >= 300 {
		t.Fatalf("the agent's %s: %q\n%s", name, line, out)
	}
}

// previewHeld reads the merge attempt the agent printed.
func previewHeld(t *testing.T, out string) reply {
	t.Helper()
	var r reply
	line := lineOf(out, "merge ")
	if !strings.HasPrefix(line, "merge 403 ") || json.Unmarshal([]byte(strings.TrimPrefix(line, "merge 403 ")), &r) != nil {
		t.Fatalf("the agent's raw merge: %q", line)
	}
	return r
}

func previewHas(list []string, want string) bool {
	return strings.Contains(","+strings.Join(list, ",")+",", ","+want+",")
}

// previewVerified exports a bundle of sel and verifies it with `pclaw
// verify`, offline, with the trust file, once the server's workers have
// chained and checkpointed what it holds, and requires every check to have
// passed, with the Sigstore trusted root of the local fake log and timestamp
// authority. Two checks are not available by construction on a first check:
// the ML-DSA cosignature (the trust file pins no ML-DSA checkpoint key) and
// the witness check against an earlier checkpoint (--previous, which a first
// check has none of); they are the only ones allowed to be so.
func previewVerified(t *testing.T, p *proof, ctx context.Context, name, sigstore string, sel evapp.Selection) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		file, _ := p.export(t, ctx, name, sel, 0)
		code, r := p.verify(t, file, "--sigstore-trusted-root", sigstore)
		var notPassed []string
		for _, c := range r.Checks {
			if c.Status != bundle.Passed && c.Name != "checkpoint.cosignature" && c.Name != "witness.previous" {
				notPassed = append(notPassed, c.Name+" "+string(c.Status))
			}
		}
		if code == 0 && len(r.Checks) > 0 && len(notPassed) == 0 {
			return
		}
		if time.Now().After(deadline) || r.Failed() {
			t.Fatalf("pclaw verify %s: exit %d, not passed: %v\n%+v", name, code, notPassed, r.Checks)
		}
		if _, err := p.jobs.Insert(context.Background(), checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestE2E_Preview_ThreeRoutesThreeStops(t *testing.T) {
	m := startM9(t)
	c, e := dockertest.Client(t)
	m.agentImage = dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/test/e2e/testdata/previewagent", "test/e2e/testdata/previewagent.Dockerfile")

	// The "coding to production" template protects the repository: alice,
	// who owns the agent, applies it with the roles it needs.
	alice := m.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'")
	for _, role := range []td.RoleName{td.RolePolicyAuthor, td.RolePolicyPublisher} {
		if code, out, errs := m.alice.pclaw(t, "role", "bind", "--role", string(role), "--user", alice); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, out, errs)
		}
	}
	m.db.AdminExec(t, "UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1", m.org)
	if code, out, errs := m.alice.pclaw(t, "template", "apply", "coding-to-production", "--repos", ghRepo, "--yes"); code != 0 {
		t.Fatalf("template apply: %d %s %s", code, out, errs)
	}
	if mode := m.row(t, "SELECT access_mode || ' ' || default_mode FROM pc.connections WHERE id = $1", m.gh.conn); mode != "pantherclaw_held enforce" {
		t.Fatalf("the GitHub connection: %s", mode)
	}

	// The workspace the developer hands the agent holds a PAT (.env, from
	// startM9) and an SSH key (not a real one).
	if err := os.MkdirAll(filepath.Join(m.workspace, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Repeat("Z", 64) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(m.workspace, ".ssh", "id_ed25519"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}

	// Step 0: the agent reads, branches, writes and opens a pull request
	// through the edge: all allowed.
	main := m.gh.sim.Branch(ghRepo, "main")
	code, out, errs := m.sandbox(t, pclaw.Options{}, "setup", ghRepo, main)
	if code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox session 1: %d\n%s\n%s", code, out, errs)
	}
	for _, step := range []string{"read", "branch", "write", "pr"} {
		previewLineOK(t, out, step)
	}
	pr, ok := m.gh.sim.PullRequest(ghRepo, 1)
	if !ok || pr.Head != "preview/fix" || pr.HeadSHA == "" || pr.Merged {
		t.Fatalf("the pull request the agent opened: %+v %v", pr, ok)
	}
	number, head := 1, pr.HeadSHA

	// Step 1: the MCP route. The merge has no independent review: held.
	mcp := m.ghMergeMCP(t, number, head)
	var mcpClass, mcpDecision, mcpTxn string
	var mcpReasons []string
	member(t, mcp, "error_class", &mcpClass)
	member(t, mcp, "decision", &mcpDecision)
	member(t, mcp, "reasons", &mcpReasons)
	member(t, mcp, "transaction_id", &mcpTxn)
	if mcpClass != "held" || mcpDecision != "REQUIRE_APPROVAL" || !previewHas(mcpReasons, "MERGES_NEED_AN_INDEPENDENT_REVIEW") {
		t.Fatalf("MCP merge: %s %s %v", mcpClass, mcpDecision, mcpReasons)
	}
	if p, _ := m.gh.sim.PullRequest(ghRepo, number); p.Merged {
		t.Fatal("merged by the MCP route while held")
	}

	// The agent's operations have traffic and a first assessment, as in
	// the M9 exit (mergeScope); the seeded instance then goes, so that the
	// sandbox's is the agent's only one.
	m.revokeSeeded(t)
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(5 * time.Second) {
		by, missing := previewCoverage(t, m), []string{}
		for _, op := range previewOps {
			if r, ok := by[op]; !ok || r.State == "COVERAGE_STATE_UNKNOWN" {
				missing = append(missing, op)
			}
		}
		if len(missing) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("operations never assessed: %v of %+v", missing, by)
		}
	}

	// Steps 2 and 3: the same pull request, attacked from inside the sandbox.
	before := len(m.gh.sim.Requests())
	code, out, errs = m.sandbox(t, pclaw.Options{}, "attack", ghRepo, strconv.Itoa(number), head)
	mm := closurePassed.FindStringSubmatch(out)
	if code != 0 || mm == nil {
		t.Fatalf("sandbox session 2: %d\n%s\n%s", code, out, errs)
	}
	curl := previewHeld(t, out)
	if curl.ErrorClass != mcpClass || curl.Decision != mcpDecision || !sameSet(curl.Reasons, mcpReasons) {
		t.Fatalf("raw %s %s %v, MCP %s %s %v", curl.ErrorClass, curl.Decision, curl.Reasons, mcpClass, mcpDecision, mcpReasons)
	}
	if curl.TransactionID == mcpTxn {
		t.Fatal("the raw merge is the MCP merge's own transaction")
	}
	raw, viaMCP := m.heldAction(t, curl.TransactionID), m.heldAction(t, mcpTxn)
	if raw.Channel != "http" || viaMCP.Channel != "mcp" || raw.AgentInstance == viaMCP.AgentInstance {
		t.Fatalf("channels %s and %s, instances %s and %s", raw.Channel, viaMCP.Channel, raw.AgentInstance, viaMCP.AgentInstance)
	}
	if a, b := normalized(t, raw, viaMCP), normalized(t, viaMCP, viaMCP); a != b {
		t.Fatalf("the raw merge is another action:\n%s\n%s", a, b)
	}
	if raw.DedupeKey == "" || raw.DedupeKey != viaMCP.DedupeKey {
		t.Fatalf("dedupe keys %q and %q", raw.DedupeKey, viaMCP.DedupeKey)
	}
	if rawHold, mcpHold := m.heldBinding(t, curl.TransactionID), m.heldBinding(t, mcpTxn); rawHold != mcpHold {
		t.Fatalf("the holds differ:\nraw %+v\nMCP %+v", rawHold, mcpHold)
	}
	// Step 3: the push attempts failed. HTTPS to github.com is refused by
	// the edge, SSH has no route, and nothing the agent did in this
	// session wrote to GitHub: the merge is held, the refs are as step 0
	// left them.
	for _, name := range []string{"https-push-advertise", "https-push"} {
		if l := lineOf(out, name+" "); !strings.HasPrefix(l, name+" error") && !strings.HasPrefix(l, name+" 403") {
			t.Fatalf("git push over HTTPS (%s): %q", name, l)
		}
	}
	if l := lineOf(out, "ssh-key "); l != "ssh-key found true" {
		t.Fatalf("the planted SSH key: %q", l)
	}
	for _, addr := range []string{"github.com:22", "140.82.112.3:22"} {
		if l := lineOf(out, "ssh "+addr); l != "ssh "+addr+" blocked" {
			t.Fatalf("git push over SSH: %q", l)
		}
	}
	for _, r := range m.gh.sim.Requests()[before:] {
		// Minting and revoking the installation token the gateway reads with are no writes to a repository.
		if (r.Write && strings.HasPrefix(r.Path, "/repos/")) || strings.Contains(r.Path, "git-receive-pack") {
			t.Fatalf("GitHub saw a write after the attack began: %+v", r)
		}
		if r.Token != "" && r.Installation == 0 {
			t.Fatalf("GitHub saw a personal token: %+v", r)
		}
	}
	if m.gh.sim.Branch(ghRepo, "main") != main || m.gh.sim.Branch(ghRepo, "preview/fix") != head {
		t.Fatal("a ref moved")
	}
	if p, _ := m.gh.sim.PullRequest(ghRepo, number); p.Merged {
		t.Fatal("merged while held")
	}
	if strings.Contains(m.logs.String(), strings.Repeat("Q", 36)) {
		t.Fatal("the PAT reached the server's logs")
	}

	// Step 4 (attempts 1 and 2): the receipts of each verify offline.
	p := m.proof(t)
	auditor := m.person(t, "preview-auditor", td.RoleAuditor).ctx
	attempts := map[string]ids.UUID{"mcp": mustUUID(t, mcpTxn), "curl": mustUUID(t, curl.TransactionID)}
	for _, id := range attempts {
		p.checkpointed(t, id)
	}
	sigstore := p.anchor(t)
	for name, id := range attempts {
		previewVerified(t, p, auditor, name+".json", sigstore, evapp.Selection{Transactions: []ids.UUID{id}})
	}

	// Step 5: the coverage card, for every operation the flow used.
	for deadline := time.Now().Add(4 * time.Minute); ; time.Sleep(5 * time.Second) {
		by, bad := previewCoverage(t, m), []string{}
		for _, op := range previewOps {
			r := by[op]
			exp, err := time.Parse(time.RFC3339, r.ExpireTime)
			if r.State != enforced || err != nil || !exp.After(time.Now()) || exp.After(time.Now().Add(24*time.Hour+time.Minute)) || r.ClosureID != mm[1] {
				bad = append(bad, op+": "+r.State+" until "+r.ExpireTime+" closure "+r.ClosureID)
			}
		}
		if len(bad) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not ENFORCED from closure %s with an expiry within 24 h:\n%s", mm[1], strings.Join(bad, "\n"))
		}
	}
}
