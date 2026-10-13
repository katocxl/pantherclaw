// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubfacts

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/sim/github"
)

const deployWorkflow = "on:\n  push:\n    branches: [main]\njobs:\n  deploy: {runs-on: x, environment: production}\n"

type ghWorld struct {
	sim  *github.Server
	srv  *httptest.Server
	head string
}

// newGHWorld is acme/payments with a deploy-on-push workflow on main, a
// branch fix/a pushed by alice and mallory, and pull request 1 from it.
func newGHWorld(t *testing.T) *ghWorld {
	t.Helper()
	sim := github.New(slog.New(slog.DiscardHandler))
	sim.CreateRepo("acme/payments", "main", map[string]string{"README.md": "# p\n", ".github/workflows/deploy.yml": deployWorkflow})
	sim.PushAs("acme/payments", "fix/a", "alice", map[string]string{"a.go": "package a\n"})
	head := sim.PushAs("acme/payments", "fix/a", "mallory", map[string]string{"b.go": "package b\n"})
	sim.AddToken("ghp_reader", "reader", []string{"acme/payments"}, map[string]string{
		"metadata": "read", "contents": "read", "pull_requests": "write", "checks": "read",
	})
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	w := &ghWorld{sim: sim, srv: srv, head: head}
	if status := w.post(t, "/repos/acme/payments/pulls", `{"title":"Fix","head":"fix/a","base":"main"}`); status != http.StatusCreated {
		t.Fatalf("open: %d", status)
	}
	return w
}

func (w *ghWorld) post(t *testing.T, path, body string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, w.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "token ghp_reader")
	res, err := w.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

// get is the Getter a fact read uses, with a read token placed.
func (w *ghWorld) get(ctx context.Context, path string) (egress.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, w.srv.URL+path, nil)
	req.Header.Set("Authorization", "token ghp_reader")
	res, err := w.srv.Client().Do(req)
	if err != nil {
		return egress.Response{}, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return egress.Response{Status: res.StatusCode, Body: b}, err
}

func facts(list []Fact) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, f := range list {
		out[f.Name] = f.Value
	}
	return out
}

// TestHR160_PullRequestFacts: the head, its people by GitHub user id, the
// latest review per reviewer on the head, the head's checks, the base
// branch's rules, and the deploy triggers of merging, all from GitHub.
func TestHR160_PullRequestFacts(t *testing.T) {
	w := newGHWorld(t)
	w.sim.AddReview("acme/payments", 1, "bob", "APPROVED", w.head)
	w.sim.AddReview("acme/payments", 1, "carol", "APPROVED", "0000000000000000000000000000000000000000")
	w.sim.SetCheckRuns("acme/payments", w.head, github.CheckRun{Name: "test", Status: "completed", Conclusion: "success"})
	w.sim.SetBranchRules("acme/payments", "main", map[string]any{"type": "pull_request", "parameters": map[string]any{"required_approving_review_count": 2}})
	pr := Subject{Owner: "acme", Repo: "payments", Number: 1}
	got := facts(Read(context.Background(), w.get, pr, []string{PullHead, PullPeople, PullReviews, PullChecks, BranchRules, RepoTriggers}))
	if len(got) != 6 {
		t.Fatalf("read %d facts: %v", len(got), got)
	}
	if h := got[PullHead]; h["sha"] != w.head || h["base"] != "main" || h["changes_workflows"] != false {
		t.Errorf("head %v", h)
	}
	people := got[PullPeople]
	if people["complete"] != true || len(people["pushers"].([]any)) != 2 || len(people["authors"].([]any)) != 2 {
		t.Errorf("people %v", people)
	}
	if r := got[PullReviews]; len(r["approved"].([]any)) != 1 {
		t.Errorf("reviews: only bob's is on the head: %v", r)
	}
	if c := got[PullChecks]; c["passed"] != true {
		t.Errorf("checks %v", c)
	}
	if r := got[BranchRules]; r["required_approvals"] != int64(2) {
		t.Errorf("rules %v", r)
	}
	if d := got[RepoTriggers]; d["state"] != "triggered" || !slices.Contains(d["environments"].([]any), any("production")) {
		t.Errorf("triggers %v", d)
	}
	// A new commit moves the head: the approval is for another commit, and
	// the new head has no check run yet, which is not a pass.
	w.sim.PushAs("acme/payments", "fix/a", "mallory", map[string]string{"c.go": "package c\n"})
	got = facts(Read(context.Background(), w.get, pr, []string{PullReviews, PullChecks}))
	if len(got[PullReviews]["approved"].([]any)) != 0 || got[PullChecks]["passed"] != false || got[PullChecks]["total"] != int64(0) {
		t.Fatalf("after a push: %v", got)
	}
}

// TestHR206_AWorkflowChangeIsUnknown: a pull request that changes a
// workflow, or a workflow the parser cannot evaluate, gives an unknown
// deploy trigger, never none; a branch that no workflow deploys is none.
func TestHR206_AWorkflowChangeIsUnknown(t *testing.T) {
	w := newGHWorld(t)
	w.sim.PushAs("acme/payments", "fix/a", "mallory", map[string]string{".github/workflows/deploy.yml": deployWorkflow + "# changed\n"})
	got := facts(Read(context.Background(), w.get, Subject{Owner: "acme", Repo: "payments", Number: 1}, []string{RepoTriggers}))
	if d := got[RepoTriggers]; d["state"] != "unknown" || d["unknown"] == nil {
		t.Fatalf("a changed workflow: %v", d)
	}
	main := w.sim.Branch("acme/payments", "main")
	for branch, want := range map[string]string{"main": "triggered", "fix/b": "none"} {
		got := facts(Read(context.Background(), w.get, Subject{Owner: "acme", Repo: "payments", Branch: branch, At: main}, []string{BranchTriggers}))
		if got[BranchTriggers]["state"] != want {
			t.Errorf("%s: %v", branch, got)
		}
	}
}

// TestHR160_AFailedReadReportsNothing: a fact whose read fails is left
// out, never guessed.
func TestHR160_AFailedReadReportsNothing(t *testing.T) {
	w := newGHWorld(t)
	failing := func(ctx context.Context, path string) (egress.Response, error) {
		if strings.Contains(path, "/activity") || strings.Contains(path, "/check-runs") {
			return egress.Response{Status: http.StatusInternalServerError}, nil
		}
		return w.get(ctx, path)
	}
	got := facts(Read(context.Background(), failing, Subject{Owner: "acme", Repo: "payments", Number: 1}, []string{PullPeople, PullChecks, PullHead}))
	if _, ok := got[PullChecks]; ok || got[PullHead] == nil {
		t.Fatalf("checks should be missing, head present: %v", got)
	}
	if got[PullPeople]["complete"] != false {
		t.Fatalf("people without the activity feed must be incomplete: %v", got[PullPeople])
	}
}

// TestHR206_AMergeDeploysWhatTheBaseBranchDeploys: without a workflow
// change, a merge leaves the base branch's workflows, read at its head, so
// a deploy added to main after the pull request's branch was cut counts.
func TestHR206_AMergeDeploysWhatTheBaseBranchDeploys(t *testing.T) {
	w := newGHWorld(t)
	w.sim.Push("acme/payments", "main", map[string]string{".github/workflows/release.yml": "on: push\njobs: {r: {environment: staging}}\n"})
	got := facts(Read(context.Background(), w.get, Subject{Owner: "acme", Repo: "payments", Number: 1}, []string{RepoTriggers}))
	d := got[RepoTriggers]
	if d["state"] != "triggered" || d["at"] != w.sim.Branch("acme/payments", "main") || !slices.Contains(d["environments"].([]any), any("staging")) {
		t.Fatalf("triggers %v", d)
	}
}

// TestHR207_PeopleAreIncompleteWhenWhoPushedIsUnknown: a commit whose
// author GitHub links to no account, or a branch created at a commit its
// creator did not make (someone pushed it first, elsewhere), makes the
// people incomplete; accounts that are not people are listed as bots, and
// author and pushers are always there.
func TestHR207_PeopleAreIncompleteWhenWhoPushedIsUnknown(t *testing.T) {
	w := newGHWorld(t)
	pr := Subject{Owner: "acme", Repo: "payments", Number: 1}
	people := facts(Read(context.Background(), w.get, pr, []string{PullPeople}))[PullPeople]
	if people["complete"] != true || people["author"] == nil || len(people["bots"].([]any)) != 0 {
		t.Fatalf("people of a plain pull request: %v", people)
	}
	w.sim.PushBy("acme/payments", "fix/a", "mallory", "", "mallory", map[string]string{"d.go": "package d\n"})
	if people := facts(Read(context.Background(), w.get, pr, []string{PullPeople}))[PullPeople]; people["complete"] != false {
		t.Fatalf("a commit whose author is linked to no account: %v", people)
	}

	// Rachel pushes a commit authored as alice to r/tmp; an App creates a
	// branch at it and opens the pull request. Rachel pushed it, but the
	// head branch's activity shows only the App.
	sha := w.sim.PushBy("acme/payments", "r/tmp", "rachel", "alice", "alice", map[string]string{"e.go": "package e\n"})
	w.sim.AddToken("ghs_app", "agent[bot]", []string{"acme/payments"}, map[string]string{"contents": "write", "pull_requests": "write"})
	for _, c := range [][2]string{
		{"/repos/acme/payments/git/refs", `{"ref":"refs/heads/fix/r","sha":"` + sha + `"}`},
		{"/repos/acme/payments/pulls", `{"title":"Fix","head":"fix/r","base":"main"}`},
	} {
		path, body := c[0], c[1]
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, w.srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "token ghs_app")
		res, err := w.srv.Client().Do(req)
		if err != nil || res.StatusCode != http.StatusCreated {
			t.Fatalf("%s: %v %v", path, res, err)
		}
		_ = res.Body.Close()
	}
	people = facts(Read(context.Background(), w.get, Subject{Owner: "acme", Repo: "payments", Number: 2}, []string{PullPeople}))[PullPeople]
	if people["complete"] != false || len(people["bots"].([]any)) != 1 || len(people["pushers"].([]any)) != 1 {
		t.Fatalf("a branch created at a commit someone else pushed: %v", people)
	}
}

// TestHR160_ChecksPassOnlyWithTheRequiredRunsFromTheirApp: no run is no
// pass; a check the base branch requires passes only with a successful run
// from the App the rule names, so a run of that name from another App does
// not count.
func TestHR160_ChecksPassOnlyWithTheRequiredRunsFromTheirApp(t *testing.T) {
	w := newGHWorld(t)
	pr := Subject{Owner: "acme", Repo: "payments", Number: 1}
	if c := facts(Read(context.Background(), w.get, pr, []string{PullChecks}))[PullChecks]; c["passed"] != false {
		t.Fatalf("no run: %v", c)
	}
	w.sim.SetBranchRules("acme/payments", "main", map[string]any{"type": "required_status_checks", "parameters": map[string]any{
		"required_status_checks": []any{map[string]any{"context": "test", "integration_id": 15368}},
	}})
	w.sim.SetCheckRuns("acme/payments", w.head,
		github.CheckRun{Name: "lint", Status: "completed", Conclusion: "success"},
		github.CheckRun{Name: "test", Status: "completed", Conclusion: "success", App: "spoofer"})
	c := facts(Read(context.Background(), w.get, pr, []string{PullChecks}))[PullChecks]
	if c["passed"] != false || len(c["missing"].([]any)) != 1 || len(c["runs"].([]any)) != 2 {
		t.Fatalf("a required check run by another App: %v", c)
	}
	w.sim.SetBranchRules("acme/payments", "main", map[string]any{"type": "required_status_checks", "parameters": map[string]any{
		"required_status_checks": []any{map[string]any{"context": "lint"}},
	}})
	if c := facts(Read(context.Background(), w.get, pr, []string{PullChecks}))[PullChecks]; c["passed"] != true {
		t.Fatalf("a required check with a successful run: %v", c)
	}
}
