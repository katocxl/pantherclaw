// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && sandbox

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	covapp "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
	"github.com/katocxl/pantherclaw/internal/server"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M9 exit (G0 M9 B6): the real server, gateway and GitHub simulator,
// and `pclaw sandbox run` with real Docker containers. Each test opens its
// own stack and sandbox. The agent is the seeded one, whose only active
// instance is the sandbox's once its seeded workload instance is revoked
// (coverage counts an agent sandboxed only when every active instance is,
// design decision 2). Run by `task test:sandbox` (tags integration and
// sandbox, PC_TEST_SANDBOX=1, the test database).

// m9 is a stack whose github connection a sandbox maps (api.github.com),
// with the images `pclaw sandbox run` needs and a person who runs it.
type m9 struct {
	*stack
	alice                        *user
	agent, grant                 string
	agentImage, edgeImage, probe string
	workspace                    string
}

func startM9(t *testing.T) *m9 {
	t.Helper()
	c, e := dockertest.Client(t)
	m := &m9{
		agentImage: dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/test/e2e/testdata/m9agent", "test/e2e/testdata/m9agent.Dockerfile"),
		edgeImage:  dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile"),
		probe:      dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-probe", "deploy/sandbox/probe.Dockerfile"),
	}
	p := inProcessIdP(t)
	// A coverage claim gets a second on this shared test machine; the
	// default (50 ms) is for a server sized for its load.
	m.stack = start(t, options{budget: "1000.00", people: &p, github: true, claimTimeout: time.Second})
	people := &m2Stack{url: m.apiURL, cfg: m.serverCfg, idp: p}
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", m.serverCfg, "--org", m.org.String()}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	m.alice = people.user(t, "alice", "alice@example.test")
	m.alice.login(t, m.org.String(), pciToken.FindStringSubmatch(out.String())[1])
	m.query(t, "SELECT agent_id::text, id::text FROM pc.grants ORDER BY created_at LIMIT 1", nil, &m.agent, &m.grant)
	// Alice owns the agent, maps the connection, runs and admits the
	// sandbox and reads coverage: the roles a team lead holds.
	alice := m.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'")
	for _, role := range []td.RoleName{td.RoleGatewayAdmin, td.RoleAgentOwner, td.RoleAgentAdmitter, td.RoleSecurityAdmin, td.RoleGrantIssuer} {
		if code, out, errs := m.alice.pclaw(t, "role", "bind", "--role", string(role), "--user", alice); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, out, errs)
		}
	}
	m.db.AdminExec(t, "UPDATE pc.role_bindings SET created_at = now() - interval '30 days' WHERE org_id = $1", m.org)
	m.db.AdminExec(t, "UPDATE pc.agents SET owner_user_id = $3 WHERE org_id = $1 AND id = $2", m.org, mustUUID(t, m.agent), mustUUID(t, alice))
	// The run's principal is its launcher: alice issues the grant she runs
	// the sandbox under, with the seeded grant's GitHub operations and
	// merge requirements.
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
		"--bounds-file", bounds, "--requirements-file", reqs, "--task", "m9 exit")
	g := grantID.FindStringSubmatch(out2)
	if code != 0 || g == nil {
		t.Fatalf("grant issue: %d %s %s", code, out2, errs)
	}
	m.grant = g[1]

	// The sandbox maps api.github.com to the github connection (G0 M9).
	m.mapAgentHost(t, "api.github.com")

	// The workspace a developer hands the agent: a PAT left in its .env.
	m.workspace = t.TempDir()
	pat := "ghp_" + strings.Repeat("Q", 36)
	if err := os.WriteFile(filepath.Join(m.workspace, ".env"), []byte("GITHUB_TOKEN="+pat+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

// mapAgentHost replaces the github connection's agent hosts, as a gateway
// admin does, and waits for the gateway to have the configuration.
func (m *m9) mapAgentHost(t *testing.T, hosts ...string) {
	t.Helper()
	rev := m.row(t, "SELECT revision::text FROM pc.connections WHERE id = $1", m.gh.conn)
	args := []string{"connection", "update", m.gh.conn.String(), "--revision", rev}
	for _, h := range hosts {
		args = append(args, "--agent-host", h)
	}
	if code, out, errs := m.alice.pclaw(t, args...); code != 0 {
		t.Fatalf("connection update: %d %s %s", code, out, errs)
	}
	m.waitConfig(t, m.configVersion(t, m.gatewayID(t)))
}

// openPR opens a pull request as the seeded workload and returns its
// number and head.
func (m *m9) openPR(t *testing.T) (int, string) {
	t.Helper()
	main := m.gh.sim.Branch(ghRepo, "main")
	if code, r, _ := m.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/git/refs", `{"ref":"refs/heads/fix/cve","sha":"`+main+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("branch: %d %+v", code, r)
	}
	if code, r, _ := m.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/pulls", `{"title":"Fix the parser","head":"fix/cve","base":"main"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("open: %d %+v", code, r)
	}
	pr, _ := m.gh.sim.PullRequest(ghRepo, 1)
	return 1, pr.HeadSHA
}

// revokeSeeded revokes the seeded workload instance, so that the agent's
// only active instance is the sandbox's.
func (m *m9) revokeSeeded(t *testing.T) {
	t.Helper()
	id := m.row(t, "SELECT id::text FROM pc.agent_instances WHERE agent_id = $1 AND state = 'ADMITTED'", m.agent)
	if code, out, errs := m.alice.pclaw(t, "instance", "revoke", id, "--reason", "the agent runs in the sandbox from now on"); code != 0 {
		t.Fatalf("instance revoke: %d %s %s", code, out, errs)
	}
}

// sandbox runs `pclaw sandbox run` as alice with the agent's arguments and
// returns its exit code, output and errors.
func (m *m9) sandbox(t *testing.T, opts pclaw.Options, agentArgs ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"sandbox", "run", "--agent", m.agent, "--connection", m.gh.conn.String(), "--grant", m.grant, "--gateway", m.gateway,
		"--image", m.agentImage, "--edge-image", m.edgeImage, "--probe-image", m.probe, "--workspace", m.workspace, "--ttl", "1h", "--",
	}, agentArgs...)
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	code := pclaw.Run(ctx, args, &out, &errb, m.alice.env(), opts)
	if code != 0 {
		logs := m.logs.String()
		t.Logf("server log tail: %s", logs[max(0, len(logs)-6000):])
	}
	return code, out.String(), errb.String()
}

var (
	closurePassed = regexp.MustCompile(`connection ` + uuidRE + `: sandbox closure PASSED \(closure (` + uuidRE + `)\), evidence for ENFORCED until (\S+)`)
	closureFailed = regexp.MustCompile(`connection ` + uuidRE + `: sandbox closure FAILED \(closure ` + uuidRE + `\)`)
	refusedRoutes = regexp.MustCompile(`the edge refused or stripped (\d+) routes of the agent`)
)

var grantID = regexp.MustCompile(`"id":\s*"(` + uuidRE + `)"`)

const uuidRE = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// card is the coverage card of a scope as `pclaw coverage show` prints it.
type card struct {
	Record struct {
		State      string   `json:"state"`
		ExpireTime string   `json:"expireTime"`
		ClosureID  string   `json:"closureId"`
		Reasons    []string `json:"reasons"`
		LastValid  *struct {
			SnapshotID  string `json:"snapshotId"`
			LapseReason string `json:"lapseReason"`
		} `json:"lastValid"`
	} `json:"record"`
}

// coverage reassesses the github connection for the agent, as the
// server's periodic job does every minute, and returns the card of the
// agent's merge scope.
func (m *m9) coverage(t *testing.T) card {
	t.Helper()
	if code, out, errs := m.alice.pclaw(t, "coverage", "reassess", m.gh.conn.String(), "--agent", m.agent); code != 0 {
		t.Fatalf("coverage reassess: %d %s %s", code, out, errs)
	}
	code, out, errs := m.alice.pclaw(t, "coverage", "show", m.agent, m.gh.conn.String(), "github.pull.merge")
	var c card
	if code != 0 || json.Unmarshal([]byte(out), &c, json.RejectUnknownMembers(false)) != nil {
		t.Fatalf("coverage show: %d %s %s", code, out, errs)
	}
	return c
}

const enforced = "COVERAGE_STATE_ENFORCED"

// heldAction is the action an approval request holds for txn.
func (m *m9) heldAction(t *testing.T, txn string) actionir.ActionIR {
	t.Helper()
	var raw []byte
	m.query(t, "SELECT action_ir FROM pc.approval_requests WHERE transaction_id = $1 ORDER BY created_at DESC LIMIT 1", []any{txn}, &raw)
	p, err := actionir.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p.Action
}

// TestE2E_M9_RawCurlSameDecision: a raw PUT to /pulls/<n>/merge from inside
// `pclaw sandbox run`, which the edge intercepts and signs as the agent's
// sandbox instance, is the same github.pull.merge action as the GitHub MCP
// server's merge_pull_request call: the same operation, target, canonical
// parameters, destinations, dedupe key, route and definition, the action
// hash once channel and per-call ids are one call's (F099). Both are held
// for the reviewer with the same decision and reasons.
func TestE2E_M9_RawCurlSameDecision(t *testing.T) {
	m := startM9(t)
	number, head := m.openPR(t)
	mcp := m.ghMergeMCP(t, number, head)
	var mcpClass, mcpDecision, mcpTxn string
	var mcpReasons []string
	member(t, mcp, "error_class", &mcpClass)
	member(t, mcp, "decision", &mcpDecision)
	member(t, mcp, "reasons", &mcpReasons)
	member(t, mcp, "transaction_id", &mcpTxn)
	if mcpClass != "held" || mcpDecision != "REQUIRE_APPROVAL" {
		t.Fatalf("MCP merge: %s %s %v", mcpClass, mcpDecision, mcpReasons)
	}
	m.revokeSeeded(t)

	code, out, errs := m.sandbox(t, pclaw.Options{}, "merge", ghRepo, strconv.Itoa(number), head)
	if code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	var curl reply
	line := lineOf(out, "merge ")
	if !strings.HasPrefix(line, "merge 403 ") || json.Unmarshal([]byte(strings.TrimPrefix(line, "merge 403 ")), &curl) != nil {
		t.Fatalf("the agent's raw merge: %q", line)
	}
	if curl.ErrorClass != mcpClass || curl.Decision != mcpDecision || !sameSet(curl.Reasons, mcpReasons) {
		t.Fatalf("raw %s %s %v, MCP %s %s %v", curl.ErrorClass, curl.Decision, curl.Reasons, mcpClass, mcpDecision, mcpReasons)
	}
	if p, _ := m.gh.sim.PullRequest(ghRepo, number); p.Merged {
		t.Fatal("merged while held")
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
	// The same hold: the same requirements, and the digests of the
	// definition and the material facts the approver is shown, none of
	// which depend on the channel.
	rawHold, mcpHold := m.heldBinding(t, curl.TransactionID), m.heldBinding(t, mcpTxn)
	if rawHold != mcpHold {
		t.Fatalf("the holds differ:\nraw %+v\nMCP %+v", rawHold, mcpHold)
	}
}

// hold is what a held action's approval request binds that the channel
// does not change (PAP-1 §8).
type hold struct {
	requirements, approvers, definition, facts string
}

func (m *m9) heldBinding(t *testing.T, txn string) hold {
	t.Helper()
	var requirements, input []byte
	m.query(t, "SELECT requirements, binding_input FROM pc.approval_requests WHERE transaction_id = $1 ORDER BY created_at DESC LIMIT 1", []any{txn}, &requirements, &input)
	var b apdomain.ActionBinding
	if err := json.Unmarshal(input, &b); err != nil {
		t.Fatal(err)
	}
	approvers, err := json.Marshal(b.ApproverRequirements)
	if err != nil {
		t.Fatal(err)
	}
	// Each instance acts under its own grant, which the requirements' sources
	// name; the rest must be equal.
	return hold{
		requirements: sourceGrant.ReplaceAllString(string(requirements), "grant <id>"),
		approvers:    string(approvers), definition: b.DefinitionDigest, facts: b.MaterialFactsDigest,
	}
}

var sourceGrant = regexp.MustCompile(`grant ` + uuidRE)

// normalized is a's action hash with b's channel and per-call ids: what is
// left is the action itself.
func normalized(t *testing.T, a, b actionir.ActionIR) string {
	t.Helper()
	a.Channel, a.RunID, a.ActionID, a.AgentInstance, a.Connection = b.Channel, b.RunID, b.ActionID, b.AgentInstance, b.Connection
	p, err := actionir.Encode(a)
	if err != nil {
		t.Fatal(err)
	}
	return p.HashHex()
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !strings.Contains(","+strings.Join(b, ",")+",", ","+x+",") {
			return false
		}
	}
	return true
}

func lineOf(out, prefix string) string {
	for l := range strings.Lines(out) {
		if strings.HasPrefix(l, prefix) {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// TestE2E_M9_FoundCredentialPushFails: the agent finds a PAT in its
// workspace and tries to push with it. git over HTTPS to github.com is
// refused by the edge (no mapped host), SSH has no route by name or by
// address, the probes' canary saw nothing of the sandbox (the closure
// passed), and the PAT sent to the API is stripped and reported, with the
// refusal, as routes the edge saw; the request goes on as the agent's
// sandbox instance, never with the PAT.
func TestE2E_M9_FoundCredentialPushFails(t *testing.T) {
	m := startM9(t)
	m.revokeSeeded(t)
	code, out, errs := m.sandbox(t, pclaw.Options{}, "push", ghRepo)
	if code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	if l := lineOf(out, "https-push "); !strings.HasPrefix(l, "https-push error") && !strings.HasPrefix(l, "https-push 403") {
		t.Fatalf("git push over HTTPS: %q", l)
	}
	for _, addr := range []string{"github.com:22", "140.82.112.3:22"} {
		if l := lineOf(out, "ssh "+addr); l != "ssh "+addr+" blocked" {
			t.Fatalf("git push over SSH: %q", l)
		}
	}
	if l := lineOf(out, "api-with-pat "); l == "" || strings.HasPrefix(l, "api-with-pat error") {
		t.Fatalf("the API with the PAT: %q", l)
	}
	if strings.Contains(m.logs.String(), strings.Repeat("Q", 36)) {
		t.Fatal("the PAT reached the server's logs")
	}
	// Every request GitHub saw came with an installation token the gateway
	// minted, never with a personal token.
	for _, r := range m.gh.sim.Requests() {
		if r.Token != "" && r.Installation == 0 {
			t.Fatalf("GitHub saw a personal token: %+v", r)
		}
	}
	mm := refusedRoutes.FindStringSubmatch(errs)
	if mm == nil {
		t.Fatalf("no routes reported:\n%s", errs)
	}
	if n, _ := strconv.Atoi(mm[1]); n < 2 {
		t.Fatalf("%d routes reported, want the refused github.com and the stripped PAT:\n%s", n, errs)
	}
}

// TestE2E_M9_EnforcedFromProbes: after a passing sandbox run the coverage
// card of the agent's GitHub merge scope reads ENFORCED from the probes'
// closure, with its expiry. The merge the agent then asks for is decided
// under that claim: its decision receipt carries the coverage claim, and
// `pclaw verify` checks it offline against the snapshot ledger.
func TestE2E_M9_EnforcedFromProbes(t *testing.T) {
	m := startM9(t)
	number, head := m.mergeScope(t)
	p := m.proof(t)
	if c := m.coverage(t); c.Record.State == enforced {
		t.Fatalf("ENFORCED before any sandbox run: %+v", c.Record)
	}
	code, out, errs := m.sandbox(t, pclaw.Options{}, "merge", ghRepo, strconv.Itoa(number), head, "3")
	mm := closurePassed.FindStringSubmatch(out)
	if code != 0 || mm == nil {
		t.Fatalf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	until, err := time.Parse(time.RFC3339, mm[2])
	if err != nil || until.Before(time.Now().Add(23*time.Hour)) || until.After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("evidence until %s: %v", mm[2], err)
	}
	c := m.enforcedSoon(t)
	if c.Record.State != enforced || c.Record.ExpireTime == "" || c.Record.ClosureID != mm[1] {
		t.Fatalf("the coverage card: %+v\nchanges: %s\nroutes: %s", c.Record,
			m.row(t, "SELECT string_agg(kind || ' ' || coalesce(detail, ''), '; ' ORDER BY id) FROM pc.coverage_invalidations WHERE connection_id = $1", m.gh.conn),
			m.row(t, "SELECT string_agg(kind || ' ' || coalesce(channel, '') || ' ' || coalesce(locator, '') || ' ' || coalesce(operation, ''), '; ') FROM pc.coverage_routes WHERE connection_id = $1", m.gh.conn))
	}

	// The agent asked three times, a second apart. A claim is computed
	// within coverage.claim_timeout of the decision (1 s here, 50 ms by
	// default), or the receipt says it is unavailable (design decision 7: a
	// slow coverage read never delays a decision); the first receipt that
	// carries one is checked.
	var txn ids.UUID
	for l := range strings.Lines(out) {
		var held reply
		if !strings.HasPrefix(l, "merge 403 ") || json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(l, "merge 403 "))), &held) != nil {
			continue
		}
		jws := m.row(t, "SELECT receipt_jws FROM pc.decision_receipts WHERE transaction_id = $1", held.TransactionID)
		parts := strings.Split(jws, ".")
		if len(parts) != 3 {
			t.Fatalf("decision receipt %q", jws)
		}
		claim, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(claim, []byte(`"coverage"`)) && bytes.Contains(claim, []byte(`"snapshot"`)) {
			txn = mustUUID(t, held.TransactionID)
			break
		}
	}
	if txn.IsZero() {
		t.Fatalf("no decision receipt of the agent's merges carries a coverage claim:\n%s", out)
	}
	p.checkpointed(t, txn)
	auditor := m.person(t, "m9-auditor", td.RoleAuditor).ctx
	// The bundle holds the claimed snapshot's ledger entry once the
	// server's workers chained and checkpointed it, as they do the receipts.
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		file, _ := p.export(t, auditor, "m9.json", evapp.Selection{Transactions: []ids.UUID{txn}}, 0)
		code, r := p.verify(t, file)
		if code == 0 && all(r, "receipt.coverage", bundle.Passed) {
			return
		}
		if time.Now().After(deadline) || some(r, "receipt.coverage", bundle.Failed) {
			t.Fatalf("pclaw verify exit %d: receipt.coverage %v\n%+v\nsnapshots: %s", code, statuses(r, "receipt.coverage"), r.Checks,
				m.row(t, `SELECT string_agg(s.id::text || ' ' || s.state || ' ' || e.kind || ' ' || coalesce(c.seq::text, 'unchained'), '; ' ORDER BY s.id)
					FROM pc.coverage_snapshots s JOIN pc.ledger_entries e ON e.org_id = s.org_id AND e.id = s.ledger_entry_id
					LEFT JOIN pc.ledger_chain c ON c.org_id = s.org_id AND c.entry_id = s.ledger_entry_id
					WHERE s.connection_id = $1 AND s.operation = 'github.pull.merge'`, m.gh.conn))
		}
		if _, err := p.jobs.Insert(context.Background(), checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
	}
}

// TestE2E_M9_ChangeDropsToPartial: a scope ENFORCED from a sandbox run
// reads PARTIAL at once when its connection changes, with the last valid
// record; and, read past its evidence's expiry, PARTIAL too, with the last
// valid record (design decision 3).
func TestE2E_M9_ChangeDropsToPartial(t *testing.T) {
	m := startM9(t)
	number, head := m.mergeScope(t)
	if code, out, errs := m.sandbox(t, pclaw.Options{}, "merge", ghRepo, strconv.Itoa(number), head); code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	if c := m.enforcedSoon(t); c.Record.State != enforced {
		t.Fatalf("the coverage card after the run: %+v", c.Record)
	}

	// Expiry: the same record read a day later.
	svc := &covapp.Service{
		Pool: m.pool, Freshness: covdomain.Freshness{EnforcedTTL: 24 * time.Hour, ReassessEvery: time.Minute},
		Clock: clock.NewFake(time.Now().Add(25 * time.Hour)),
	}
	reader := m.person(t, "m9-reader", td.RoleAuditor).ctx
	rec, err := svc.GetCoverage(reader, covdomain.Scope{Agent: mustUUID(t, m.agent), Connection: m.gh.conn, Operation: "github.pull.merge"})
	if err != nil || rec.State == covdomain.Enforced || rec.LastValid == nil || rec.Lapse != covdomain.LapseExpired {
		t.Fatalf("a day later: %s, last valid %v, lapse %q, %v", rec.State, rec.LastValid != nil, rec.Lapse, err)
	}

	// A change to the connection: PARTIAL at once, with the last valid
	// record.
	m.mapAgentHost(t, "api.github.com", "uploads.github.com")
	c := m.coverage(t)
	if c.Record.State != "COVERAGE_STATE_PARTIAL" || c.Record.LastValid == nil || c.Record.LastValid.SnapshotID == "" {
		t.Fatalf("the coverage card after the connection changed: %+v", c.Record)
	}
}

// TestE2E_M9_AFailedNegativeControlBlocksPromotion: a sandbox whose probe is
// attached to an open network on purpose (Docker's default bridge) reaches
// the canary; the negative controls fail, the closure is FAILED, and the
// scope never reads ENFORCED.
func TestE2E_M9_AFailedNegativeControlBlocksPromotion(t *testing.T) {
	m := startM9(t)
	m.revokeSeeded(t)
	open := func(ctx context.Context, container string) error {
		out, err := exec.CommandContext(ctx, "docker", "network", "connect", "bridge", container).CombinedOutput()
		if err != nil {
			t.Logf("docker network connect: %s", out)
		}
		return err
	}
	code, out, errs := m.sandbox(t, pclaw.Options{SandboxBeforeProbe: open}, "push", ghRepo)
	if !closureFailed.MatchString(out) || closurePassed.MatchString(out) {
		t.Fatalf("sandbox run on an open network: %d\n%s\n%s", code, out, errs)
	}
	if c := m.coverage(t); c.Record.State == enforced {
		t.Fatalf("a failed closure promoted the scope: %+v", c.Record)
	}
	if n := m.row(t, "SELECT count(*)::text FROM pc.coverage_invalidations WHERE kind = 'closure_failed' AND connection_id = $1", m.gh.conn); n == "0" {
		t.Fatal("no closure_failed invalidation")
	}
}

// mergeScope opens a pull request and asks to merge it over MCP as the
// seeded workload (held): the agent's merge scope then has traffic, which
// the coverage job assesses (it runs every minute; here at once). It then
// revokes the seeded instance, so that the agent's only instance is the
// sandbox's, and returns the pull request.
func (m *m9) mergeScope(t *testing.T) (int, string) {
	t.Helper()
	number, head := m.openPR(t)
	m.ghMergeMCP(t, number, head)
	m.revokeSeeded(t)
	// The inventory reads traffic a minute behind the clock, so a
	// transaction still committing is never skipped.
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(5 * time.Second) {
		c := m.coverage(t)
		if c.Record.State == enforced {
			t.Fatalf("the merge scope before any sandbox run: %+v", c.Record)
		}
		if c.Record.State != "COVERAGE_STATE_UNKNOWN" {
			return number, head
		}
		if time.Now().After(deadline) {
			t.Fatalf("the merge scope was never assessed: %+v", c.Record)
		}
	}
}

// enforcedSoon waits until the card reads ENFORCED: the closure promoted
// the scope at once, and the changes it was opened after (the session's
// own, the connection's setup) are marked by the server's reassessment
// job, which runs every minute; until then any change keeps it PARTIAL.
func (m *m9) enforcedSoon(t *testing.T) card {
	t.Helper()
	for deadline := time.Now().Add(4 * time.Minute); ; time.Sleep(5 * time.Second) {
		c := m.coverage(t)
		if c.Record.State == enforced {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("the coverage card never read ENFORCED: %+v\nchanges: %s", c.Record,
				m.row(t, `SELECT string_agg(kind || ' ' || coalesce(detail, '') || ' ' || (reassessed_at IS NULL)::text, '; ' ORDER BY id)
					FROM pc.coverage_invalidations WHERE connection_id = $1`, m.gh.conn))
		}
	}
}
