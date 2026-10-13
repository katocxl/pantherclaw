// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// list answers a GET whose body is a JSON array.
func (w *world) list(path, auth string) (int, []map[string]any) {
	w.t.Helper()
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodGet, w.srv.URL+path, nil)
	req.Header.Set("Authorization", auth)
	resp, err := w.srv.Client().Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out []map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestFactSources: the reads behind the gateway's GitHub facts answer as
// GitHub does: branch rules, check runs at a commit, workflow files,
// environments with reviewers, a pull request's commits with their
// authors, and who pushed which ref.
func TestFactSources(t *testing.T) {
	w := newWorld(t)
	w.sim.Install(Installation{ID: 9, Account: "acme", Repos: []string{"payments"}, Permissions: map[string]string{
		"metadata": "read", "contents": "write", "pull_requests": "write", "checks": "read", "actions": "read", "deployments": "read",
	}})
	status, out := w.do(http.MethodPost, "/app/installations/9/access_tokens", "Bearer "+w.jwt(), ``)
	if status != http.StatusCreated {
		t.Fatalf("mint: %d", status)
	}
	auth := "Bearer " + out["token"].(string)
	w.sim.SetBranchRules("acme/payments", "main", map[string]any{"type": "pull_request", "parameters": map[string]any{"required_approving_review_count": 1}})
	w.sim.SetCheckRuns("acme/payments", w.head, CheckRun{Name: "test", Status: "completed", Conclusion: "success"})
	w.sim.SetEnvironments("acme/payments", Environment{Name: "production", Reviewers: []string{"rachel"}})
	second := w.sim.PushAs("acme/payments", "fix/a", "mallory", map[string]string{"x.go": "package x\n"})
	if status, _ := w.do(http.MethodPost, "/repos/acme/payments/pulls", auth, `{"title":"Fix","head":"fix/a","base":"main"}`); status != http.StatusCreated {
		t.Fatalf("open: %d", status)
	}

	if status, out := w.do(http.MethodGet, "/repos/acme/payments/branches/fix/a", auth, ""); status != http.StatusOK || out["commit"].(map[string]any)["sha"] != second {
		t.Fatalf("branch: %d %v", status, out)
	}
	if status, rules := w.list("/repos/acme/payments/rules/branches/main", auth); status != http.StatusOK || len(rules) != 1 || rules[0]["type"] != "pull_request" {
		t.Fatalf("rules: %d %v", status, rules)
	}
	if status, out := w.do(http.MethodGet, "/repos/acme/payments/commits/"+w.head+"/check-runs", auth, ""); status != http.StatusOK || out["total_count"] != float64(1) {
		t.Fatalf("checks: %d %v", status, out)
	}
	if status, out := w.do(http.MethodGet, "/repos/acme/payments/actions/workflows", auth, ""); status != http.StatusOK || out["total_count"] != float64(1) {
		t.Fatalf("workflows: %d %v", status, out)
	}
	status, out = w.do(http.MethodGet, "/repos/acme/payments/environments", auth, "")
	if status != http.StatusOK || !strings.Contains(strings.ToLower(jsonText(out)), "rachel") {
		t.Fatalf("environments: %d %v", status, out)
	}
	status, commits := w.list("/repos/acme/payments/pulls/1/commits", auth)
	if status != http.StatusOK || len(commits) != 2 || commits[0]["sha"] != w.head || commits[1]["sha"] != second ||
		commits[1]["author"].(map[string]any)["login"] != "mallory" {
		t.Fatalf("commits: %d %v", status, commits)
	}
	status, pushes := w.list("/repos/acme/payments/activity?ref=refs/heads/fix/a", auth)
	if status != http.StatusOK || len(pushes) != 2 || pushes[0]["actor"].(map[string]any)["login"] != "mallory" ||
		pushes[1]["activity_type"] != "branch_creation" {
		t.Fatalf("activity: %d %v", status, pushes)
	}
	// A token without checks:read is refused there.
	_, narrow := w.mint(`{"repositories":["payments"],"permissions":{"contents":"read"}}`)
	if status, _ := w.do(http.MethodGet, "/repos/acme/payments/commits/"+w.head+"/check-runs", "Bearer "+narrow, ""); status != http.StatusForbidden {
		t.Fatalf("checks without the permission: %d", status)
	}
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestDeploymentsSettle: a push to a branch that deploys on push starts a
// deployment, pending until it settles.
func TestDeploymentsSettle(t *testing.T) {
	w := newWorld(t)
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	w.sim.WithClock(func() time.Time { return now })
	w.sim.DeployOnPush("acme/payments", "main", "production", time.Minute)
	sha := w.sim.Push("acme/payments", "main", map[string]string{"a.go": "package a\n"})
	deps := w.sim.Deployments("acme/payments")
	if len(deps) != 1 || deps[0].SHA != sha || deps[0].Environment != "production" || deps[0].state(now) != "pending" {
		t.Fatalf("deployments %+v", deps)
	}
	now = now.Add(2 * time.Minute)
	if deps[0].state(now) != "success" {
		t.Fatal("the deployment did not settle")
	}
}

// TestFaults: the token endpoint can fail or grant wider than asked, and a
// merge can lose its answer after it happened.
func TestFaults(t *testing.T) {
	w := newWorld(t)
	w.sim.SetFaults(Faults{TokenStatus: http.StatusInternalServerError})
	if status, _ := w.mint(`{"repositories":["payments"],"permissions":{"contents":"read"}}`); status != http.StatusInternalServerError {
		t.Fatalf("token failure: %d", status)
	}
	w.sim.SetFaults(Faults{WiderGrant: true})
	status, out := w.do(http.MethodPost, "/app/installations/7/access_tokens", "Bearer "+w.jwt(), `{"repositories":["payments"],"permissions":{"contents":"read"}}`)
	if status != http.StatusCreated || len(out["repositories"].([]any)) != 2 || out["permissions"].(map[string]any)["contents"] != "write" {
		t.Fatalf("wider grant: %d %v", status, out)
	}
	w.sim.SetFaults(Faults{LoseMerge: true})
	auth := "Bearer " + out["token"].(string)
	if status, _ := w.do(http.MethodPost, "/repos/acme/payments/pulls", auth, `{"title":"Fix","head":"fix/a","base":"main"}`); status != http.StatusCreated {
		t.Fatalf("open: %d", status)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, w.srv.URL+"/repos/acme/payments/pulls/1/merge", strings.NewReader(`{"sha":"`+w.head+`"}`))
	req.Header.Set("Authorization", auth)
	if resp, err := w.srv.Client().Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a lost merge answered %d", resp.StatusCode)
	}
	if p, _ := w.sim.PullRequest("acme/payments", 1); !p.Merged {
		t.Fatal("the lost merge did not happen")
	}
}

// factWorld is newWorld with an installation that may read every fact
// source, and a token of it.
func factWorld(t *testing.T) (*world, string) {
	w := newWorld(t)
	w.sim.Install(Installation{ID: 9, Account: "acme", Repos: []string{"payments"}, Permissions: map[string]string{
		"metadata": "read", "contents": "write", "pull_requests": "write", "checks": "read", "actions": "read", "deployments": "read",
	}})
	status, out := w.do(http.MethodPost, "/app/installations/9/access_tokens", "Bearer "+w.jwt(), ``)
	if status != http.StatusCreated {
		t.Fatalf("mint: %d", status)
	}
	return w, "Bearer " + out["token"].(string)
}

// TestAuthorCommitterAndPusherAreApart: one person can push a commit whose
// git author is another, a git email may be linked to no account (null),
// and every account says whether it is a User or a Bot (HR-207).
func TestAuthorCommitterAndPusherAreApart(t *testing.T) {
	w, auth := factWorld(t)
	w.sim.PushBy("acme/payments", "fix/a", "bob", "alice", "", map[string]string{"y.go": "package y\n"})
	if status, _ := w.do(http.MethodPost, "/repos/acme/payments/pulls", auth, `{"title":"Fix","head":"fix/a","base":"main"}`); status != http.StatusCreated {
		t.Fatalf("open: %d", status)
	}
	_, commits := w.list("/repos/acme/payments/pulls/1/commits", auth)
	last := commits[len(commits)-1]
	if a, _ := last["author"].(map[string]any); a["login"] != "alice" || a["type"] != "User" || last["committer"] != nil {
		t.Fatalf("commit %v", last)
	}
	_, pushes := w.list("/repos/acme/payments/activity?ref=fix/a", auth)
	if a, _ := pushes[0]["actor"].(map[string]any); a["login"] != "bob" || a["id"] != float64(accountID("bob")) {
		t.Fatalf("pusher %v", pushes[0])
	}
	_, pr := w.do(http.MethodGet, "/repos/acme/payments/pulls/1", auth, "")
	if u, _ := pr["user"].(map[string]any); u["login"] != "pantherclaw-sim[bot]" || u["type"] != "Bot" {
		t.Fatalf("the App's pull request author: %v", pr["user"])
	}
}

// TestListsArePagedAndRunsNameTheirApp: lists answer per_page items (30 by
// default) with a Link header while more follow, as GitHub pages them; a
// check run names the App that posted it.
func TestListsArePagedAndRunsNameTheirApp(t *testing.T) {
	w, auth := factWorld(t)
	w.sim.SetPageSize(2)
	w.sim.SetCheckRuns("acme/payments", w.head,
		CheckRun{Name: "a", Status: "completed", Conclusion: "success"}, CheckRun{Name: "b", Status: "completed", Conclusion: "success"},
		CheckRun{Name: "test", Status: "completed", Conclusion: "success", App: "spoofer"})
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+"/repos/acme/payments/commits/"+w.head+"/check-runs?per_page=100", nil)
	req.Header.Set("Authorization", auth)
	resp, err := w.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var first map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = json.Unmarshal(raw, &first)
	if runs, _ := first["check_runs"].([]any); len(runs) != 2 || first["total_count"] != float64(3) || !strings.Contains(resp.Header.Get("Link"), `rel="next"`) {
		t.Fatalf("page 1: %v, Link %q", first, resp.Header.Get("Link"))
	}
	_, last := w.do(http.MethodGet, "/repos/acme/payments/commits/"+w.head+"/check-runs?per_page=100&page=2", auth, "")
	runs, _ := last["check_runs"].([]any)
	if len(runs) != 1 || runs[0].(map[string]any)["app"].(map[string]any)["slug"] != "spoofer" {
		t.Fatalf("page 2: %v", last)
	}
}

// TestDeploymentStatesAreInTheirStatuses: as on GitHub, a deployment
// carries no state; its statuses say pending, then success once it
// settled.
func TestDeploymentStatesAreInTheirStatuses(t *testing.T) {
	w, auth := factWorld(t)
	now := time.Now()
	w.sim.WithClock(func() time.Time { return now })
	w.sim.DeployOnPush("acme/payments", "main", "production", time.Minute)
	w.sim.Push("acme/payments", "main", map[string]string{"a.go": "package a\n"})
	_, deps := w.list("/repos/acme/payments/deployments", auth)
	if len(deps) != 1 || deps[0]["state"] != nil {
		t.Fatalf("deployments %v", deps)
	}
	path := "/repos/acme/payments/deployments/" + strconv.FormatInt(int64(deps[0]["id"].(float64)), 10) + "/statuses"
	if _, sts := w.list(path, auth); len(sts) != 1 || sts[0]["state"] != "pending" {
		t.Fatalf("statuses before settling %v", sts)
	}
	now = now.Add(2 * time.Minute)
	if _, sts := w.list(path, auth); len(sts) != 2 || sts[0]["state"] != "success" {
		t.Fatalf("statuses after settling %v", sts)
	}
}
