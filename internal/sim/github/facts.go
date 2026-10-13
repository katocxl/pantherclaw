// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// CheckRun is a check run on a commit.
type CheckRun struct {
	Name       string
	Status     string // queued, in_progress or completed
	Conclusion string // success, failure, neutral, skipped, … when completed
	// App is the slug of the App that posted it, github-actions when empty:
	// any App with checks: write can post a run of any name.
	App string
}

// Environment is a deployment environment and the people who must approve
// deployments to it.
type Environment struct {
	Name      string
	Reviewers []string
}

// Deployment is a deployment a push to a branch started. It is pending
// until SettleAfter has passed, then success.
type Deployment struct {
	ID          int64
	SHA, Ref    string
	Environment string
	Created     time.Time
	SettleAfter time.Duration
}

// state is the deployment's state at now.
func (d Deployment) state(now time.Time) string {
	if now.Before(d.Created.Add(d.SettleAfter)) {
		return "pending"
	}
	return "success"
}

// Push is one entry of a repository's activity feed: who moved which ref.
type Push struct {
	ID           int64
	Ref          string
	Before       string
	After        string
	Pusher       string
	ActivityType string // push, branch_creation or pr_merge
	At           time.Time
}

// deployOn is a branch whose pushes start a deployment.
type deployOn struct {
	environment string
	settle      time.Duration
}

// facts is the per-repository state the gateway reads as facts (G0 M8,
// G4): branch rules, check runs, environments, deployments and pushes.
type facts struct {
	rules       map[string][]map[string]any // branch → rules as GitHub returns them
	checks      map[string][]CheckRun       // commit → check runs
	envs        []Environment
	deployOn    map[string]deployOn // branch → deployment started by a push
	deployments []Deployment
	activity    []Push
}

func (r *Repo) state() *facts {
	if r.facts == nil {
		r.facts = &facts{rules: map[string][]map[string]any{}, checks: map[string][]CheckRun{}, deployOn: map[string]deployOn{}}
	}
	return r.facts
}

// SetBranchRules sets the rules GET .../rules/branches/{branch} answers,
// each as GitHub returns it ({"type": "pull_request", "parameters": {…}}).
func (s *Server) SetBranchRules(fullName, branch string, rules ...map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(fullName)].state().rules[branch] = rules
}

// SetCheckRuns sets the check runs of a commit.
func (s *Server) SetCheckRuns(fullName, sha string, runs ...CheckRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(fullName)].state().checks[sha] = runs
}

// SetEnvironments sets a repository's environments.
func (s *Server) SetEnvironments(fullName string, envs ...Environment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(fullName)].state().envs = envs
}

// DeployOnPush makes every push to branch start a deployment to
// environment that settles after settle: what a workflow on push with an
// environment does on GitHub.
func (s *Server) DeployOnPush(fullName, branch, environment string, settle time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(fullName)].state().deployOn[branch] = deployOn{environment: environment, settle: settle}
}

// Deployments returns a repository's deployments, oldest first.
func (s *Server) Deployments(fullName string) []Deployment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.repos[strings.ToLower(fullName)].state().deployments)
}

// pushed records a ref moving to after by pusher, and starts a deployment
// when the branch deploys on push.
func (s *Server) pushed(r *Repo, branch, before, after, pusher, kind string) {
	f := r.state()
	s.seq++
	if before == "" {
		kind = "branch_creation"
	}
	f.activity = append(f.activity, Push{
		ID: s.seq, Ref: "refs/heads/" + branch, Before: before, After: after, Pusher: pusher, ActivityType: kind, At: s.now(),
	})
	if d, ok := f.deployOn[branch]; ok {
		s.seq++
		f.deployments = append(f.deployments, Deployment{
			ID: s.seq, SHA: after, Ref: branch, Environment: d.environment, Created: s.now(), SettleAfter: d.settle,
		})
	}
}

// factRoutes registers the reads behind the gateway's GitHub facts, with
// the permissions GitHub documents for each.
func (s *Server) factRoutes(mux *http.ServeMux) {
	for _, rt := range []route{
		{"GET /repos/{owner}/{repo}/rules/branches/{branch...}", "metadata", "read", s.branchRules},
		{"GET /repos/{owner}/{repo}/branches/{branch...}", "contents", "read", s.getBranch},
		{"GET /repos/{owner}/{repo}/commits/{ref}/check-runs", "checks", "read", s.checkRuns},
		{"GET /repos/{owner}/{repo}/actions/workflows", "actions", "read", s.workflows},
		{"GET /repos/{owner}/{repo}/environments", "actions", "read", s.environments},
		{"GET /repos/{owner}/{repo}/deployments", "deployments", "read", s.listDeployments},
		{"GET /repos/{owner}/{repo}/deployments/{id}/statuses", "deployments", "read", s.deploymentStatuses},
		{"GET /repos/{owner}/{repo}/activity", "metadata", "read", s.activity},
		{"GET /repos/{owner}/{repo}/pulls/{number}/commits", "pull_requests", "read", s.pullCommits},
		{"GET /repos/{owner}/{repo}/pulls/{number}/files", "pull_requests", "read", s.pullFiles},
	} {
		mux.HandleFunc(rt.pattern, s.guard(rt))
	}
}

func (s *Server) branchRules(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	rules := r.state().rules[req.PathValue("branch")]
	if rules == nil {
		rules = []map[string]any{}
	}
	return reply(w, http.StatusOK, rules)
}

func (s *Server) checkRuns(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	sha := req.PathValue("ref")
	if c := r.resolve(sha); c != nil {
		sha = c.SHA
	}
	runs := []map[string]any{}
	for i, c := range r.state().checks[sha] {
		app := c.App
		if app == "" {
			app = "github-actions"
		}
		runs = append(runs, map[string]any{
			"id": i + 1, "name": c.Name, "head_sha": sha, "status": c.Status, "conclusion": c.Conclusion,
			"app": map[string]any{"id": accountID(app), "slug": app},
		})
	}
	return reply(w, http.StatusOK, map[string]any{"total_count": len(runs), "check_runs": s.paged(w, req, runs)})
}

// workflows lists the workflow files on the default branch.
func (s *Server) workflows(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	out := []map[string]any{}
	files := r.Commits[r.Branches[r.DefaultBranch]].Files
	for i, p := range slices.Sorted(maps.Keys(files)) {
		if strings.HasPrefix(p, ".github/workflows/") && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			out = append(out, map[string]any{"id": i + 1, "name": p[len(".github/workflows/"):], "path": p, "state": "active"})
		}
	}
	return reply(w, http.StatusOK, map[string]any{"total_count": len(out), "workflows": s.paged(w, req, out)})
}

func (s *Server) environments(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	out := []map[string]any{}
	for i, e := range r.state().envs {
		var reviewers []map[string]any
		for _, login := range e.Reviewers {
			reviewers = append(reviewers, map[string]any{"type": "User", "reviewer": map[string]any{"login": login, "id": accountID(login)}})
		}
		rules := []map[string]any{}
		if len(reviewers) > 0 {
			rules = append(rules, map[string]any{"type": "required_reviewers", "reviewers": reviewers})
		}
		out = append(out, map[string]any{"id": i + 1, "name": e.Name, "protection_rules": rules})
	}
	return reply(w, http.StatusOK, map[string]any{"total_count": len(out), "environments": s.paged(w, req, out)})
}

// listDeployments lists deployments, newest first, filtered by sha, ref or
// environment. As on GitHub, a deployment carries no state: that is in its
// statuses.
func (s *Server) listDeployments(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	q := req.URL.Query()
	out := []map[string]any{}
	deps := r.state().deployments
	for i := len(deps) - 1; i >= 0; i-- {
		d := deps[i]
		if (q.Get("sha") != "" && q.Get("sha") != d.SHA) || (q.Get("ref") != "" && q.Get("ref") != d.Ref) ||
			(q.Get("environment") != "" && q.Get("environment") != d.Environment) {
			continue
		}
		out = append(out, map[string]any{
			"id": d.ID, "sha": d.SHA, "ref": d.Ref, "environment": d.Environment,
			"created_at": d.Created.UTC().Format(time.RFC3339),
		})
	}
	return reply(w, http.StatusOK, s.paged(w, req, out))
}

// deploymentStatuses lists a deployment's statuses, newest first: pending
// when it was created, then success once it settled.
func (s *Server) deploymentStatuses(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	id, _ := strconv.ParseInt(req.PathValue("id"), 10, 64)
	i := slices.IndexFunc(r.state().deployments, func(d Deployment) bool { return d.ID == id })
	if i < 0 {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	d := r.state().deployments[i]
	out := []map[string]any{{"id": 2 * d.ID, "state": "pending", "environment": d.Environment, "created_at": d.Created.UTC().Format(time.RFC3339)}}
	if d.state(s.now()) == "success" {
		settled := d.Created.Add(d.SettleAfter)
		out = append([]map[string]any{{"id": 2*d.ID + 1, "state": "success", "environment": d.Environment, "created_at": settled.UTC().Format(time.RFC3339)}}, out...)
	}
	return reply(w, http.StatusOK, s.paged(w, req, out))
}

// activity lists who moved which ref, newest first (GitHub's repository
// activity API), filtered by ref.
func (s *Server) activity(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	ref := req.URL.Query().Get("ref")
	out := []map[string]any{}
	acts := r.state().activity
	for i := len(acts) - 1; i >= 0; i-- {
		a := acts[i]
		if ref != "" && ref != a.Ref && "refs/heads/"+ref != a.Ref {
			continue
		}
		out = append(out, map[string]any{
			"id": a.ID, "ref": a.Ref, "before": a.Before, "after": a.After, "activity_type": a.ActivityType,
			"timestamp": a.At.UTC().Format(time.RFC3339), "actor": account(a.Pusher),
		})
	}
	return reply(w, http.StatusOK, s.paged(w, req, out))
}

// pullCommits lists the commits a pull request adds to its base: those
// reachable from the head and not from the base, oldest first, each with
// its author and committer (null for an email linked to no account). As
// on GitHub, the list stops at 250 commits.
func (s *Server) pullCommits(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	p := pull(r, req)
	if p == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	base := map[string]bool{}
	for stack := []string{r.Branches[p.Base]}; len(stack) > 0; {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c != "" && !base[c] {
			base[c] = true
			stack = append(stack, r.Commits[c].Parents...)
		}
	}
	var commits []*Commit
	seen := map[string]bool{}
	for stack := []string{p.HeadSHA}; len(stack) > 0; {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c == "" || base[c] || seen[c] {
			continue
		}
		seen[c] = true
		commits = append(commits, r.Commits[c])
		stack = append(stack, r.Commits[c].Parents...)
	}
	slices.Reverse(commits)
	out := []map[string]any{}
	for _, c := range commits[:min(len(commits), 250)] {
		out = append(out, map[string]any{"sha": c.SHA, "author": account(c.Author), "committer": account(c.Committer)})
	}
	return reply(w, http.StatusOK, s.paged(w, req, out))
}

// pullFiles lists the files a pull request changes: those that differ
// between the merge base and the head, as GitHub compares them. As on
// GitHub, the list stops at 3000 files.
func (s *Server) pullFiles(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	p := pull(r, req)
	if p == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	base, head := r.Commits[mergeBase(r, r.Branches[p.Base], p.HeadSHA)].Files, r.Commits[p.HeadSHA].Files
	out := []map[string]any{}
	for _, f := range slices.Sorted(maps.Keys(head)) {
		switch old, ok := base[f]; {
		case !ok:
			out = append(out, map[string]any{"filename": f, "status": "added"})
		case old != head[f]:
			out = append(out, map[string]any{"filename": f, "status": "modified"})
		}
	}
	for _, f := range slices.Sorted(maps.Keys(base)) {
		if _, ok := head[f]; !ok {
			out = append(out, map[string]any{"filename": f, "status": "removed"})
		}
	}
	return reply(w, http.StatusOK, s.paged(w, req, out[:min(len(out), 3000)]))
}

// getBranch reads one branch and its head commit.
func (s *Server) getBranch(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	name := req.PathValue("branch")
	sha := r.Branches[name]
	if sha == "" {
		return fail(w, http.StatusNotFound, "Branch not found")
	}
	return reply(w, http.StatusOK, map[string]any{"name": name, "commit": map[string]any{"sha": sha}, "simulated": true})
}
