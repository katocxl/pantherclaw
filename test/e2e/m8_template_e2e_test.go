// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/server"
)

// TestE2E_M8_C4_Template is the brief's C4 row: the "coding to production"
// template applies through the APIs only, as a person, every step audited;
// a dry run changes nothing; applying again changes nothing; something that
// differs is changed only with --update.
func TestE2E_M8_C4_Template(t *testing.T) {
	p := inProcessIdP(t)
	// The org has pc.shell too, so that the shell rule compiles, as in a real org.
	s := start(t, options{budget: "1000.00", people: &p, github: true, shell: true})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	var out, errb bytes.Buffer
	if code := server.Run(context.Background(), []string{"org", "admin-invite", "--config", s.serverCfg, "--org", s.org.String()}, &out, &errb, noEnv); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, s.org.String(), pciToken.FindStringSubmatch(out.String())[1])
	code, o, e := alice.pclaw(t, "team", "create", "--slug", "coding", "--name", "Coding")
	if code != 0 {
		t.Fatalf("team create: %d %s %s", code, o, e)
	}
	team := field(t, o, "id")
	agent := s.row(t, "SELECT id::text FROM pc.agents ORDER BY created_at LIMIT 1")
	var aliceID string
	s.query(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'", nil, &aliceID)
	// Change windows are a security admin's (HR-207); without the role the
	// plan fails, naming the step.
	if code, o, e := alice.pclaw(t, "template", "apply", "coding-to-production", "--repos", ghRepo, "--dry-run"); code == 0 ||
		!strings.Contains(e, "change window") || !strings.Contains(e, "release.window.manage") {
		t.Fatalf("a plan without release.window.manage: %d %s %s", code, o, e)
	}
	bind := func(role string) {
		t.Helper()
		if code, o, e := alice.pclaw(t, "role", "bind", "--role", role, "--user", aliceID); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	bind("security_admin")
	// Lacking a permission a change needs, nothing is applied at all.
	if code, o, e := alice.pclaw(t, "template", "apply", "coding-to-production", "--repos", ghRepo, "--yes"); code == 0 ||
		!strings.Contains(o, "You lack policy.author, policy.publish") || !strings.Contains(e, "nothing was changed") {
		t.Fatalf("an apply without policy.author: %d %s %s", code, o, e)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.release.window.created'"); n != "0" {
		t.Fatalf("a refused apply made %s window(s)", n)
	}
	for _, role := range []string{"policy_author", "policy_publisher", "grant_issuer"} {
		bind(role)
	}

	// audits counts the audit events of each kind the template makes.
	kinds := []string{"guardrails.changed", "policy.version_created", "policy.published", "release.window.created", "grant.issued", "grant.revised"}
	audits := func() map[string]string {
		m := map[string]string{}
		for _, k := range kinds {
			m[k] = s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = $1", "audit."+k)
		}
		return m
	}
	same := func(a, b map[string]string) bool {
		for _, k := range kinds {
			if a[k] != b[k] {
				return false
			}
		}
		return true
	}
	apply := func(extra ...string) (int, string, string) {
		args := []string{"template", "apply", "coding-to-production", "--repos", ghRepo, "--agent", agent, "--team", team}
		return alice.pclaw(t, append(args, extra...)...)
	}

	// Without an agent or a team, the plan says what it skips and why.
	code, o, e = alice.pclaw(t, "template", "apply", "coding-to-production", "--repos", ghRepo, "--dry-run")
	for _, want := range []string{"grant skipped: no agent", "envelope", "shell rule skipped: no agent", "Binds no people to roles"} {
		if code != 0 || !strings.Contains(o, want) {
			t.Fatalf("plan without an agent, want %q: %d %s %s", want, code, o, e)
		}
	}

	// 1. A dry run shows the plan and changes nothing.
	before := audits()
	code, o, e = apply("--dry-run")
	if code != 0 || !strings.Contains(o, "Dry run: nothing was changed.") || !strings.Contains(o, "create") ||
		!strings.Contains(o, "Protects "+ghRepo+"'s default branch main") || !strings.Contains(o, "the agent's rules hold for agent "+agent+"'s runs only") ||
		!strings.Contains(o, "capped by the org's grant ceiling of 168h0m0s") {
		t.Fatalf("dry run: %d %s %s", code, o, e)
	}
	if after := audits(); !same(before, after) {
		t.Fatalf("a dry run changed something: %v → %v", before, after)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.grants WHERE grantor_id::text = $1", aliceID); n != "0" {
		t.Fatalf("a dry run issued %s grant(s)", n)
	}

	// 2. Applying makes each change through its API, audited as alice.
	code, o, e = apply("--yes")
	if code != 0 || strings.Count(o, "Done: ") != 4 {
		t.Fatalf("apply: %d %s %s", code, o, e)
	}
	for _, k := range []string{"guardrails.changed", "policy.version_created", "policy.published", "release.window.created", "grant.issued"} {
		if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = $1 AND actor_id = $2", "audit."+k, aliceID); n != "1" {
			t.Fatalf("%s audited as alice %s time(s)", k, n)
		}
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.grants WHERE agent_id::text = $1 AND principal_user_id::text = $2 AND grantor_id::text = $2", agent, aliceID); n != "1" {
		t.Fatalf("%s grant(s) to the agent for alice, want 1", n)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.role_bindings WHERE role IN ('code_reviewer', 'release_approver')"); n != "0" {
		t.Fatalf("the template bound %s people to roles", n)
	}

	// 3. Applying again changes nothing.
	applied := audits()
	code, o, e = apply("--yes")
	if code != 0 || !strings.Contains(o, "Nothing to change") {
		t.Fatalf("re-apply: %d %s %s", code, o, e)
	}
	if after := audits(); !same(applied, after) {
		t.Fatalf("re-applying changed something: %v → %v", applied, after)
	}

	// 4. What differs is shown and left alone without --update.
	code, o, e = apply("--yes", "--time-zone", "Europe/London")
	if code == 0 || !strings.Contains(o, "differs") || !strings.Contains(e, "--update") {
		t.Fatalf("a different window without --update: %d %s %s", code, o, e)
	}
	if after := audits(); !same(applied, after) {
		t.Fatalf("a refused apply changed something: %v → %v", applied, after)
	}
	code, o, e = apply("--yes", "--time-zone", "Europe/London", "--update")
	if code != 0 || strings.Count(o, "Done: ") != 1 {
		t.Fatalf("a different window with --update: %d %s %s", code, o, e)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.release.window.created' AND actor_id = $1", aliceID); n != "2" {
		t.Fatalf("window changes audited %s time(s), want 2", n)
	}

	// 5. The template protects: an agent run on its grant prepares a change
	// and opens a pull request, but cannot write the default branch, change
	// the repository's settings or merge without a review and a release.
	bind("run_launcher")
	kf, err := workloadclient.ReadKeyFile(s.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	inst := kf.Identifier[strings.LastIndex(kf.Identifier, "/")+1:]
	grant := s.row(t, "SELECT id::text FROM pc.grants WHERE agent_id::text = $1 AND grantor_id::text = $2", agent, aliceID)
	code, o, e = alice.pclaw(t, "run", "start", agent, "--instance", inst, "--grant", grant, "--task", "template:coding-to-production")
	if code != 0 {
		t.Fatalf("run start: %d %s %s", code, o, e)
	}
	s.run = field(t, o, "id")
	main := s.gh.sim.Branch(ghRepo, "main")
	content := base64.StdEncoding.EncodeToString([]byte("package parser // fixed\n"))
	for _, ok := range []struct{ method, path, body string }{
		{http.MethodGet, "/repos/" + ghRepo + "/contents/README.md", ""},
		{http.MethodPost, "/repos/" + ghRepo + "/git/refs", `{"ref":"refs/heads/fix/c4","sha":"` + main + `"}`},
		{http.MethodPut, "/repos/" + ghRepo + "/contents/src/parser.go", `{"message":"Fix","content":"` + content + `","branch":"fix/c4"}`},
		{http.MethodPost, "/repos/" + ghRepo + "/pulls", `{"title":"Fix","head":"fix/c4","base":"main"}`},
	} {
		if code, r, _ := s.ghCall(t, ok.method, ok.path, ok.body, ids.NewV7()); code >= 300 {
			t.Fatalf("%s %s on the template's grant: %d %+v", ok.method, ok.path, code, r)
		}
	}
	for _, denied := range []struct{ method, path, body, why string }{
		{http.MethodPut, "/repos/" + ghRepo + "/contents/src/parser.go", `{"message":"Fix","content":"` + content + `","branch":"main"}`, "DEFAULT_BRANCH_WRITE"},
		{http.MethodPost, "/repos/" + ghRepo + "/git/refs", `{"ref":"refs/heads/main","sha":"` + main + `"}`, "DEFAULT_BRANCH_WRITE"},
		{http.MethodPatch, "/repos/" + ghRepo, `{"default_branch":"fix/c4"}`, ""},
	} {
		code, r, raw := s.ghCall(t, denied.method, denied.path, denied.body, ids.NewV7())
		if code != http.StatusForbidden || r.Decision != "DENY" || !strings.Contains(raw, denied.why) {
			t.Fatalf("%s %s on the template's grant: %d %s", denied.method, denied.path, code, raw)
		}
	}
	if s.gh.sim.Branch(ghRepo, "main") != main {
		t.Fatal("the default branch moved")
	}
	pr, _ := s.gh.sim.PullRequest(ghRepo, 1)
	code, held := s.ghMerge(t, ids.NewV7(), 1, pr.HeadSHA)
	if code != http.StatusForbidden || held.Decision != "REQUIRE_APPROVAL" ||
		!slices.Contains(held.Reasons, "MERGE_NEEDS_REVIEW") || !slices.Contains(held.Reasons, "DEPLOYMENT_NEEDS_RELEASE") {
		t.Fatalf("a merge on the template's grant: %d %+v", code, held)
	}
	if p, _ := s.gh.sim.PullRequest(ghRepo, 1); p.Merged {
		t.Fatal("merged while held")
	}

	// 6. Applying for another repository adds its own rules and leaves
	// this one's alone; removing it is explicit, and a repository a live
	// grant from the template covers keeps its rules.
	const other = "acme/other"
	code, o, e = alice.pclaw(t, "template", "apply", "coding-to-production", "--repos", other, "--time-zone", "Europe/London", "--yes")
	if code != 0 || !strings.Contains(o, "Done: policy version") {
		t.Fatalf("apply for %s: %d %s %s", other, code, o, e)
	}
	code, held = s.ghMerge(t, ids.NewV7(), 1, pr.HeadSHA)
	if code != http.StatusForbidden || !slices.Contains(held.Reasons, "MERGE_NEEDS_REVIEW") {
		t.Fatalf("a merge after applying for %s: %d %+v", other, code, held)
	}
	code, o, e = alice.pclaw(t, "template", "remove", "coding-to-production", "--repos", ghRepo, "--yes")
	if code == 0 || !strings.Contains(o, "still covers "+ghRepo) || !strings.Contains(e, "nothing was changed") {
		t.Fatalf("remove %s while its grant lives: %d %s %s", ghRepo, code, o, e)
	}
	before = audits()
	code, o, e = alice.pclaw(t, "template", "remove", "coding-to-production", "--repos", other, "--yes")
	if code != 0 || strings.Count(o, "  remove ") != 3 || !strings.Contains(o, "Done: policy version") {
		t.Fatalf("remove %s: %d %s %s", other, code, o, e)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.policy.published' AND actor_id = $1", aliceID); n != "3" {
		t.Fatalf("policy publications audited as alice: %s, want 3", n)
	}
	if code, o, e = alice.pclaw(t, "template", "remove", "coding-to-production", "--repos", other, "--yes"); code != 0 || !strings.Contains(o, "Nothing to remove") {
		t.Fatalf("remove %s again: %d %s %s", other, code, o, e)
	}
	code, held = s.ghMerge(t, ids.NewV7(), 1, pr.HeadSHA)
	if code != http.StatusForbidden || !slices.Contains(held.Reasons, "MERGE_NEEDS_REVIEW") {
		t.Fatalf("a merge after removing %s: %d %+v", other, code, held)
	}

	// 7. On a route in monitor mode the rules record decisions and do not
	// block: the plan says so.
	s.db.AdminExec(t, `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
		VALUES ($1, $2, 'github-pull-merge', 'monitor', 'test')
		ON CONFLICT (org_id, connection_id, route) DO UPDATE SET mode = 'monitor'`, s.org, s.gh.conn)
	code, o, e = apply("--dry-run", "--time-zone", "Europe/London")
	if code != 0 || !strings.Contains(o, "route github-pull-merge is in monitor mode: the rules are recorded but do not block") {
		t.Fatalf("a plan with a monitored route: %d %s %s", code, o, e)
	}
}
