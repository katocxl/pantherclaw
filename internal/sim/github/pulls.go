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

// Pull is a simulated pull request.
type Pull struct {
	Number         int
	Title, Body    string
	Head, Base     string
	HeadSHA        string
	Draft          bool
	State          string // open or closed
	Merged         bool
	MergeCommitSHA string
	MergeMethod    string
	Author         string
	Reviews        []Review
	// Unmergeable makes the merge answer 405 (conflicts or unmet rules).
	Unmergeable bool
}

// Review is a review of a pull request at one commit.
type Review struct {
	ID        int64
	User      string
	State     string // APPROVED, CHANGES_REQUESTED or COMMENTED
	CommitID  string
	Submitted time.Time
}

// PullRequest returns a snapshot of a pull request.
func (s *Server) PullRequest(fullName string, number int) (Pull, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.repos[strings.ToLower(fullName)]; r != nil && r.Pulls[number] != nil {
		p := *r.Pulls[number]
		p.Reviews = slices.Clone(p.Reviews)
		return p, true
	}
	return Pull{}, false
}

// AddReview records a person's review of a pull request at a commit.
func (s *Server) AddReview(fullName string, number int, user, state, commitID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr := s.repos[strings.ToLower(fullName)].Pulls[number]
	s.seq++
	pr.Reviews = append(pr.Reviews, Review{ID: s.seq, User: user, State: state, CommitID: commitID, Submitted: s.now()})
}

// SetMergeable makes a pull request mergeable or not.
func (s *Server) SetMergeable(fullName string, number int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[strings.ToLower(fullName)].Pulls[number].Unmergeable = !ok
}

func (s *Server) createPull(w http.ResponseWriter, req *http.Request, r *Repo, t *Token) int {
	var b struct {
		Title string `json:"title"`
		Body  string `json:"body"`
		Head  string `json:"head"`
		Base  string `json:"base"`
		Draft bool   `json:"draft"`
	}
	if !decode(req, &b) {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	if b.Title == "" || r.Branches[b.Head] == "" || r.Branches[b.Base] == "" || b.Head == b.Base {
		return fail(w, http.StatusUnprocessableEntity, "Validation Failed")
	}
	for _, p := range r.Pulls {
		if p.Head == b.Head && p.Base == b.Base && p.State == "open" {
			return fail(w, http.StatusUnprocessableEntity, "A pull request already exists for "+r.Owner+":"+b.Head+".")
		}
	}
	pr := &Pull{
		Number: r.nextPull, Title: b.Title, Body: b.Body, Head: b.Head, Base: b.Base, HeadSHA: r.Branches[b.Head],
		Draft: b.Draft, State: "open", Author: actor(t),
	}
	r.Pulls[pr.Number] = pr
	r.nextPull++
	return reply(w, http.StatusCreated, pullJSON(r, pr))
}

func pullJSON(r *Repo, p *Pull) map[string]any {
	var merge any
	if p.MergeCommitSHA != "" {
		merge = p.MergeCommitSHA
	}
	return map[string]any{
		"number": p.Number, "state": p.State, "title": p.Title, "body": p.Body, "draft": p.Draft,
		"merged": p.Merged, "mergeable": !p.Unmergeable && p.State == "open", "merge_commit_sha": merge,
		"user":     account(p.Author),
		"head":     map[string]any{"ref": p.Head, "sha": p.HeadSHA},
		"base":     map[string]any{"ref": p.Base, "sha": r.Branches[p.Base]},
		"html_url": "https://github.example.test/" + r.full() + "/pull/" + strconv.Itoa(p.Number), "simulated": true,
	}
}

// pull returns the pull request a path names.
func pull(r *Repo, req *http.Request) *Pull {
	n, err := strconv.Atoi(req.PathValue("number"))
	if err != nil {
		return nil
	}
	return r.Pulls[n]
}

func (s *Server) getPull(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	p := pull(r, req)
	if p == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	return reply(w, http.StatusOK, pullJSON(r, p))
}

func (s *Server) reviews(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	p := pull(r, req)
	if p == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	out := []map[string]any{}
	for _, rv := range p.Reviews {
		out = append(out, map[string]any{
			"id": rv.ID, "user": account(rv.User), "state": rv.State, "commit_id": rv.CommitID,
			"submitted_at": rv.Submitted.UTC().Format(time.RFC3339),
		})
	}
	out = s.paged(w, req, out)
	return reply(w, http.StatusOK, out)
}

// review submits a review as the token's actor, at the head unless
// commit_id names another commit.
func (s *Server) review(w http.ResponseWriter, req *http.Request, r *Repo, t *Token) int {
	p := pull(r, req)
	if p == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	var b struct {
		Event    string `json:"event"`
		CommitID string `json:"commit_id"`
		Body     string `json:"body"`
	}
	states := map[string]string{"APPROVE": "APPROVED", "REQUEST_CHANGES": "CHANGES_REQUESTED", "COMMENT": "COMMENTED"}
	if !decode(req, &b) || states[b.Event] == "" || actor(t) == p.Author {
		return fail(w, http.StatusUnprocessableEntity, "Validation Failed")
	}
	if b.CommitID == "" {
		b.CommitID = p.HeadSHA
	}
	s.seq++
	rv := Review{ID: s.seq, User: actor(t), State: states[b.Event], CommitID: b.CommitID, Submitted: s.now()}
	p.Reviews = append(p.Reviews, rv)
	return reply(w, http.StatusOK, map[string]any{"id": rv.ID, "state": rv.State, "commit_id": rv.CommitID, "user": account(rv.User)})
}

// merge merges a pull request. A sha that is not the head answers 409, as
// GitHub does; a closed, draft or unmergeable pull request answers 405; a
// pull request that changes a workflow file needs the workflows permission
// (403), as a push of one does.
func (s *Server) merge(w http.ResponseWriter, req *http.Request, r *Repo, t *Token) int {
	p := pull(r, req)
	if p == nil {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	var b struct {
		SHA           string `json:"sha"`
		MergeMethod   string `json:"merge_method"`
		CommitTitle   string `json:"commit_title"`
		CommitMessage string `json:"commit_message"`
	}
	if !decode(req, &b) {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	if b.MergeMethod == "" {
		b.MergeMethod = "merge"
	}
	allowed := map[string]bool{"merge": r.Settings.AllowMergeCommit, "squash": r.Settings.AllowSquashMerge, "rebase": r.Settings.AllowRebaseMerge}
	switch {
	case p.State != "open" || p.Draft || p.Unmergeable:
		return fail(w, http.StatusMethodNotAllowed, "Pull Request is not mergeable")
	case !allowed[b.MergeMethod]:
		return fail(w, http.StatusMethodNotAllowed, "Merge method is not allowed on this repository")
	case b.SHA != "" && b.SHA != p.HeadSHA:
		return fail(w, http.StatusConflict, "Head branch was modified. Review and try the merge again.")
	}
	base := r.Branches[p.Base]
	if f := changedWorkflow(r, base, p.HeadSHA); f != "" && !covers(t.Permissions["workflows"], "write") {
		return fail(w, http.StatusForbidden, "refusing to allow a GitHub App to create or update workflow `"+f+"` without `workflows` permission")
	}
	// The head's changes since the merge base, applied to the base, so a
	// change made on the base meanwhile is kept.
	from, to := r.Commits[mergeBase(r, base, p.HeadSHA)].Files, r.Commits[p.HeadSHA].Files
	tree := maps.Clone(r.Commits[base].Files)
	for f, c := range to {
		if from[f] != c {
			tree[f] = c
		}
	}
	for f := range from {
		if _, ok := to[f]; !ok {
			delete(tree, f)
		}
	}
	parents := []string{base, p.HeadSHA}
	if b.MergeMethod != "merge" {
		parents = []string{base}
	}
	sha := s.commit(r, actor(t), actor(t), parents, tree)
	s.advance(r, p.Base, sha, actor(t), "pr_merge")
	p.State, p.Merged, p.MergeCommitSHA, p.MergeMethod = "closed", true, sha, b.MergeMethod
	if s.faults.LoseMerge {
		panic(http.ErrAbortHandler) // merged, and the answer is lost
	}
	return reply(w, http.StatusOK, map[string]any{"sha": sha, "merged": true, "message": "Pull Request successfully merged", "simulated": true})
}

// pullRoutes registers the pull request endpoints with the permissions
// GitHub documents for each: a merge needs contents write.
func (s *Server) pullRoutes(mux *http.ServeMux) {
	for _, rt := range []route{
		{"POST /repos/{owner}/{repo}/pulls", "pull_requests", "write", s.createPull},
		{"GET /repos/{owner}/{repo}/pulls/{number}", "pull_requests", "read", s.getPull},
		{"GET /repos/{owner}/{repo}/pulls/{number}/reviews", "pull_requests", "read", s.reviews},
		{"POST /repos/{owner}/{repo}/pulls/{number}/reviews", "pull_requests", "write", s.review},
		{"PUT /repos/{owner}/{repo}/pulls/{number}/merge", "contents", "write", s.merge},
	} {
		mux.HandleFunc(rt.pattern, s.guard(rt))
	}
}

// changedWorkflow is a workflow file the head changes (adds, modifies or
// removes) since its merge base with base, or "".
func changedWorkflow(r *Repo, base, head string) string {
	from, to := r.Commits[mergeBase(r, base, head)].Files, r.Commits[head].Files
	for _, f := range slices.Sorted(maps.Keys(to)) {
		if old, ok := from[f]; strings.HasPrefix(f, ".github/workflows/") && (!ok || old != to[f]) {
			return f
		}
	}
	for _, f := range slices.Sorted(maps.Keys(from)) {
		if _, ok := to[f]; strings.HasPrefix(f, ".github/workflows/") && !ok {
			return f
		}
	}
	return ""
}

// ancestors are the commits reachable from sha, itself included.
func ancestors(r *Repo, sha string) map[string]bool {
	out := map[string]bool{}
	for stack := []string{sha}; len(stack) > 0; {
		c := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if c != "" && !out[c] {
			out[c] = true
			stack = append(stack, r.Commits[c].Parents...)
		}
	}
	return out
}

// mergeBase is the nearest commit of head's history that base's history
// also reaches.
func mergeBase(r *Repo, base, head string) string {
	in := ancestors(r, base)
	seen := map[string]bool{}
	for queue := []string{head}; len(queue) > 0; queue = queue[1:] {
		c := queue[0]
		if c == "" || seen[c] {
			continue
		}
		if in[c] {
			return c
		}
		seen[c] = true
		queue = append(queue, r.Commits[c].Parents...)
	}
	return base
}
