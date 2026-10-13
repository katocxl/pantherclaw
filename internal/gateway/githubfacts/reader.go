// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubfacts

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
)

// Fact names this reader provides, by the subject they are about.
const (
	PullHead       = "github.pull.head"
	PullPeople     = "github.pull.people"
	PullReviews    = "github.pull.reviews"
	PullChecks     = "github.pull.checks"
	BranchRules    = "github.branch.rules"
	RepoTriggers   = "github.repo.deploy_triggers"
	BranchTriggers = "github.branch.deploy_triggers"
)

// Scopes are the read-only permissions a fact read's token is minted
// with (ADR-0021 item 2).
var Scopes = map[string]string{"metadata": "read", "contents": "read", "pull_requests": "read", "checks": "read", "statuses": "read"}

// Getter reads one GitHub API path with the fact read's token placed.
type Getter func(ctx context.Context, path string) (egress.Response, error)

// Fact is one fact read, as its value's members.
type Fact struct {
	Name  string
	Value map[string]any
}

// Subject is what a fact read is about: a pull request (owner, repo and
// number), or a branch (owner, repo, branch and the commit it will be at).
type Subject struct {
	Owner, Repo string
	Number      int
	Branch, At  string
}

// Read reads the named facts about subject. A fact whose read fails is
// left out, so the decision sees it missing (HR-160, HR-206); it never
// guesses a value.
func Read(ctx context.Context, get Getter, s Subject, names []string) []Fact {
	r := &reader{get: get, s: s, repo: "/repos/" + url.PathEscape(s.Owner) + "/" + url.PathEscape(s.Repo)}
	var out []Fact
	for _, name := range names {
		v, err := r.fact(ctx, name)
		if err == nil && v != nil {
			out = append(out, Fact{Name: name, Value: v})
		}
	}
	return out
}

type reader struct {
	get        Getter
	s          Subject
	repo       string
	pull       map[string]any
	rulesRead  []map[string]any
	baseBranch map[string]any
}

func (r *reader) json(ctx context.Context, path string, v any) error {
	res, err := r.get(ctx, path)
	switch {
	case err != nil:
		return err
	case res.Status != http.StatusOK || res.Truncated:
		return fmt.Errorf("GET %s answered %d", path, res.Status)
	}
	return json.Unmarshal(res.Body, v)
}

// pullRequest reads the pull request once per Read.
func (r *reader) pullRequest(ctx context.Context) (map[string]any, error) {
	if r.pull != nil {
		return r.pull, nil
	}
	if r.s.Number == 0 {
		return nil, fmt.Errorf("not a pull request")
	}
	var p map[string]any
	if err := r.json(ctx, r.repo+"/pulls/"+strconv.Itoa(r.s.Number), &p); err != nil {
		return nil, err
	}
	r.pull = p
	return p, nil
}

func str(m map[string]any, keys ...string) string {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	s, _ := cur.(string)
	return s
}

func num(v any) int64 {
	f, _ := v.(float64)
	return int64(f)
}

func (r *reader) fact(ctx context.Context, name string) (map[string]any, error) {
	switch name {
	case PullHead:
		return r.head(ctx)
	case PullPeople:
		return r.people(ctx)
	case PullReviews:
		return r.reviews(ctx)
	case PullChecks:
		return r.checks(ctx)
	case BranchRules:
		return r.rules(ctx)
	case RepoTriggers:
		// After the merge, the base branch holds its own workflows plus the
		// pull request's changes. A change to a workflow is unknown; without
		// one, the workflows are the base branch head's, which may have
		// gained a deploy since the pull request's branch was cut.
		head, err := r.head(ctx)
		if err != nil {
			return nil, err
		}
		base, _ := head["base"].(string)
		if head["changes_workflows"] == true {
			t := Triggers{Branch: base, At: str(r.pull, "head", "sha")}
			return object(t.unknown("the pull request changes .github/workflows or .github/actions"))
		}
		at, err := BranchHead(ctx, r.get, r.s.Owner, r.s.Repo, base)
		if err != nil {
			return nil, err
		}
		return r.triggers(ctx, base, at, true)
	case BranchTriggers:
		return r.triggers(ctx, r.s.Branch, r.s.At, false)
	}
	return nil, fmt.Errorf("no reader for %s", name)
}

func (r *reader) head(ctx context.Context) (map[string]any, error) {
	p, err := r.pullRequest(ctx)
	if err != nil {
		return nil, err
	}
	var files []map[string]any
	if err := r.json(ctx, r.repo+"/pulls/"+strconv.Itoa(r.s.Number)+"/files?per_page=100", &files); err != nil {
		return nil, err
	}
	changed := num(p["changed_files"])
	// Beyond one page, a workflow change could hide on the next: assume one.
	changes := len(files) >= 100 || changed > int64(len(files))
	for _, f := range files {
		if IsWorkflowPath(str(f, "filename")) || IsWorkflowPath(str(f, "previous_filename")) {
			changes = true
		}
	}
	mergeable := "unknown"
	if b, ok := p["mergeable"].(bool); ok {
		mergeable = map[bool]string{true: "clean", false: "blocked"}[b]
	}
	draft, _ := p["draft"].(bool)
	return map[string]any{
		"sha": str(p, "head", "sha"), "base": str(p, "base", "ref"), "base_sha": str(p, "base", "sha"), "draft": draft,
		"state": str(p, "state"), "mergeable": mergeable, "changed_files": max(changed, int64(len(files))),
		"additions": num(p["additions"]), "deletions": num(p["deletions"]), "changes_workflows": changes,
	}, nil
}

// people lists, by GitHub user id, the pull request's author, its commits'
// authors and committers, and every authenticated pusher of its head
// branch, and among them the bots: accounts of GitHub type Bot (an App's
// [bot] account). An organization or a mannequin (an imported placeholder
// for a real person) is not a bot. author and pushers are always there.
// It is incomplete (design decision 18, HR-207) when a pusher may be
// missing: a fork; a commit whose author or committer GitHub links to no
// account; a head that no recorded push or branch creation moved the
// branch to, or a commit none brought; a push or branch creation that
// brought a commit its actor neither authored nor committed (someone may
// have pushed it first, to another ref); more commits or pushes than one
// page of 100; or a read that failed.
func (r *reader) people(ctx context.Context) (map[string]any, error) {
	p, err := r.pullRequest(ctx)
	if err != nil {
		return nil, err
	}
	var bots []int64
	id := func(account any) int64 {
		m := mapOf(account)
		n := num(m["id"])
		if n > 0 && str(m, "type") == "Bot" {
			bots = appendID(bots, n)
		}
		return n
	}
	author := id(p["user"])
	out := map[string]any{"complete": true, "author": author}
	incomplete := func() { out["complete"] = false }
	if author <= 0 || !strings.EqualFold(str(p, "head", "repo", "full_name"), r.s.Owner+"/"+r.s.Repo) {
		incomplete() // no author, or a fork (perhaps since deleted)
	}
	var commits []map[string]any
	if err := r.json(ctx, r.repo+"/pulls/"+strconv.Itoa(r.s.Number)+"/commits?per_page=100", &commits); err != nil || len(commits) >= 100 {
		incomplete()
	}
	var authors, committers, pushers []int64
	at := map[string]int{}
	for i, c := range commits {
		a, cm := id(c["author"]), id(c["committer"])
		if a <= 0 || cm <= 0 {
			incomplete() // an email linked to no account: who it is is unknown
		}
		authors, committers = appendID(authors, a), appendID(committers, cm)
		at[str(c, "sha")] = i
	}
	var acts []map[string]any
	ref := "refs/heads/" + str(p, "head", "ref")
	if err := r.json(ctx, r.repo+"/activity?ref="+url.QueryEscape(ref)+"&per_page=100", &acts); err != nil || len(acts) >= 100 {
		incomplete()
	}
	head := str(p, "head", "sha")
	headMoved, brought := false, make([]bool, len(commits))
	for _, a := range acts {
		actor := id(a["actor"])
		if actor <= 0 {
			incomplete()
		}
		pushers = appendID(pushers, actor)
		headMoved = headMoved || (head != "" && str(a, "after") == head)
		to, ok := at[str(a, "after")]
		if !ok {
			continue
		}
		from := 0
		if i, ok := at[str(a, "before")]; ok && i < to {
			from = i + 1
		}
		for i := from; i <= to; i++ {
			brought[i] = true
			if c := commits[i]; actor != num(mapOf(c["author"])["id"]) && actor != num(mapOf(c["committer"])["id"]) {
				incomplete() // it brought a commit it did not make: the first pusher is unknown
			}
		}
	}
	if !headMoved || slices.Contains(brought, false) {
		incomplete() // the feed does not show who pushed every commit
	}
	out["authors"], out["committers"], out["pushers"], out["bots"] = ids(authors), ids(committers), ids(pushers), ids(bots)
	return out, nil
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func appendID(list []int64, id int64) []int64 {
	if id <= 0 || slices.Contains(list, id) {
		return list
	}
	return append(list, id)
}

func ids(list []int64) []any {
	slices.Sort(list)
	out := make([]any, len(list))
	for i, v := range list {
		out[i] = v
	}
	return out
}

// reviews keeps each reviewer's latest review, and counts it only when it
// was made on the head.
func (r *reader) reviews(ctx context.Context) (map[string]any, error) {
	p, err := r.pullRequest(ctx)
	if err != nil {
		return nil, err
	}
	head := str(p, "head", "sha")
	var list []map[string]any
	if err := r.json(ctx, r.repo+"/pulls/"+strconv.Itoa(r.s.Number)+"/reviews?per_page=100", &list); err != nil {
		return nil, err
	} else if len(list) >= 100 {
		return nil, fmt.Errorf("more reviews than one page") // a later review may change the latest
	}
	latest := map[int64]map[string]any{}
	for _, rv := range list {
		if st := str(rv, "state"); st == "APPROVED" || st == "CHANGES_REQUESTED" || st == "DISMISSED" {
			latest[num(mapOf(rv["user"])["id"])] = rv
		}
	}
	var approved, changes []int64
	for id, rv := range latest {
		if str(rv, "commit_id") != head {
			continue
		}
		switch str(rv, "state") {
		case "APPROVED":
			approved = appendID(approved, id)
		case "CHANGES_REQUESTED":
			changes = appendID(changes, id)
		}
	}
	return map[string]any{"head": head, "approved": ids(approved), "changes_requested": ids(changes)}, nil
}

// checks reports the head's check runs, each with the App that posted it,
// and its commit statuses. It passed only when there is a run or a status,
// every one completed successfully, every check the base branch requires
// (by its rules, or by classic branch protection) has a successful run,
// from the App it names when it names one, or a successful status, and
// classic protection could be read; missing lists the required checks
// without one, and classic says what classic protection was found: none,
// read or unread.
func (r *reader) checks(ctx context.Context) (map[string]any, error) {
	p, err := r.pullRequest(ctx)
	if err != nil {
		return nil, err
	}
	required, err := r.requiredChecks(ctx)
	if err != nil {
		return nil, err
	}
	classic, classicRequired, err := r.classic(ctx)
	if err != nil {
		return nil, err
	}
	required = append(required, classicRequired...)
	head := str(p, "head", "sha")
	var res struct {
		Total int              `json:"total_count"`
		Runs  []map[string]any `json:"check_runs"`
	}
	if err := r.json(ctx, r.repo+"/commits/"+url.PathEscape(head)+"/check-runs?per_page=100", &res); err != nil || res.Total > len(res.Runs) {
		return nil, fmt.Errorf("check runs: %w", err)
	}
	var st struct {
		Total    int              `json:"total_count"`
		Statuses []map[string]any `json:"statuses"`
	}
	if err := r.json(ctx, r.repo+"/commits/"+url.PathEscape(head)+"/status?per_page=100", &st); err != nil || st.Total > len(st.Statuses) {
		return nil, fmt.Errorf("commit statuses: %w", err)
	}
	ok := func(c map[string]any) bool {
		return str(c, "status") == "completed" && slices.Contains([]string{"success", "neutral", "skipped"}, str(c, "conclusion"))
	}
	failing, missing, runs, statuses := []any{}, []any{}, []any{}, []any{}
	for _, c := range res.Runs {
		runs = append(runs, map[string]any{"name": str(c, "name"), "app_id": num(mapOf(c["app"])["id"])})
		if !ok(c) {
			failing = append(failing, str(c, "name"))
		}
	}
	for _, s := range st.Statuses {
		statuses = append(statuses, map[string]any{"context": str(s, "context"), "state": str(s, "state")})
		if str(s, "state") != "success" {
			failing = append(failing, str(s, "context"))
		}
	}
	for _, q := range required {
		run := slices.ContainsFunc(res.Runs, func(c map[string]any) bool {
			return str(c, "name") == q.context && ok(c) && (q.app == 0 || num(mapOf(c["app"])["id"]) == q.app)
		})
		status := q.app == 0 && slices.ContainsFunc(st.Statuses, func(s map[string]any) bool {
			return str(s, "context") == q.context && str(s, "state") == "success"
		})
		if !run && !status && !slices.Contains(missing, any(q.context)) {
			missing = append(missing, q.context)
		}
	}
	passed := len(res.Runs)+len(st.Statuses) > 0 && len(failing) == 0 && len(missing) == 0 && classic != "unread"
	return map[string]any{
		"head": head, "passed": passed, "total": int64(len(res.Runs) + len(st.Statuses)), "failing": failing, "missing": missing,
		"runs": runs, "statuses": statuses, "classic": classic,
	}, nil
}

// classic reads the classic branch protection of the pull request's base
// branch, once per Read, from the branch itself: none when the branch is
// not protected, read with its required status checks, or unread when the
// branch is protected but GitHub did not show how.
func (r *reader) classic(ctx context.Context) (string, []required, error) {
	p, err := r.pullRequest(ctx)
	if err != nil {
		return "", nil, err
	}
	if r.baseBranch == nil {
		var b map[string]any
		if err := r.json(ctx, r.repo+"/branches/"+EscapeRef(str(p, "base", "ref")), &b); err != nil {
			return "", nil, err
		}
		r.baseBranch = b
	}
	if protected, _ := r.baseBranch["protected"].(bool); !protected {
		return "none", nil, nil
	}
	protection, ok := r.baseBranch["protection"].(map[string]any)
	if !ok {
		return "unread", nil, nil
	}
	rsc := mapOf(protection["required_status_checks"])
	var out []required
	if checks := listOf(rsc["checks"]); len(checks) > 0 {
		for _, c := range checks {
			out = append(out, required{context: str(mapOf(c), "context"), app: num(mapOf(c)["app_id"])})
		}
	} else {
		for _, c := range listOf(rsc["contexts"]) {
			if s, ok := c.(string); ok {
				out = append(out, required{context: s})
			}
		}
	}
	return "read", out, nil
}

// required is a status check a branch rule requires, with the App that
// must post it (0 for any).
type required struct {
	context string
	app     int64
}

// branchRules reads the rules on the pull request's base branch once per
// Read: at most one page of 100; more is an error.
func (r *reader) branchRules(ctx context.Context) (string, []map[string]any, error) {
	p, err := r.pullRequest(ctx)
	if err != nil {
		return "", nil, err
	}
	base := str(p, "base", "ref")
	if r.rulesRead == nil {
		var rules []map[string]any
		if err := r.json(ctx, r.repo+"/rules/branches/"+EscapeRef(base)+"?per_page=100", &rules); err != nil {
			return "", nil, err
		} else if len(rules) >= 100 {
			return "", nil, fmt.Errorf("more branch rules than one page")
		}
		r.rulesRead = rules
	}
	return base, r.rulesRead, nil
}

// requiredChecks are the status checks the base branch's rules require.
func (r *reader) requiredChecks(ctx context.Context) ([]required, error) {
	_, rules, err := r.branchRules(ctx)
	if err != nil {
		return nil, err
	}
	var out []required
	for _, rule := range rules {
		if str(rule, "type") == "required_status_checks" {
			for _, c := range listOf(mapOf(rule["parameters"])["required_status_checks"]) {
				out = append(out, required{context: str(mapOf(c), "context"), app: num(mapOf(c)["integration_id"])})
			}
		}
	}
	return out, nil
}

// rules reads the base branch's rules and classic protection: the
// approvals a pull request needs (rules only: classic review requirements
// need administration permission) and the status checks that must pass.
// protection is the classic protection found: none, read or unread.
func (r *reader) rules(ctx context.Context) (map[string]any, error) {
	base, rules, err := r.branchRules(ctx)
	if err != nil {
		return nil, err
	}
	classic, classicRequired, err := r.classic(ctx)
	if err != nil {
		return nil, err
	}
	approvals := int64(0)
	checks := []any{}
	var kinds []any
	for _, rule := range rules {
		kind := str(rule, "type")
		kinds = append(kinds, kind)
		params := mapOf(rule["parameters"])
		switch kind {
		case "pull_request":
			approvals = max(approvals, num(params["required_approving_review_count"]))
		case "required_status_checks":
			for _, c := range listOf(params["required_status_checks"]) {
				checks = append(checks, str(mapOf(c), "context"))
			}
		}
	}
	for _, c := range classicRequired {
		if !slices.Contains(checks, any(c.context)) {
			checks = append(checks, c.context)
		}
	}
	if kinds == nil {
		kinds = []any{}
	}
	return map[string]any{"branch": base, "required_approvals": approvals, "required_checks": checks, "rules": kinds, "protection": classic}, nil
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

// BranchHead reads the commit a branch is at.
func BranchHead(ctx context.Context, get Getter, owner, repo, branch string) (string, error) {
	var b struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	r := &reader{get: get}
	if err := r.json(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/branches/"+EscapeRef(branch), &b); err != nil {
		return "", err
	}
	if b.Commit.SHA == "" {
		return "", fmt.Errorf("branch %s has no head", branch)
	}
	return b.Commit.SHA, nil
}

// EscapeRef escapes each segment of a branch name for a path.
func EscapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// triggers reads the workflow files at a commit and decides whether the
// operation, a push to branch or a merge into it, deploys (DeployTriggers).
func (r *reader) triggers(ctx context.Context, branch, at string, merge bool) (map[string]any, error) {
	if branch == "" || at == "" {
		return nil, fmt.Errorf("no branch or commit")
	}
	t := Triggers{State: "unknown", Branch: branch, At: at}
	var listing []map[string]any
	res, err := r.get(ctx, r.repo+"/contents/.github/workflows?ref="+url.QueryEscape(at))
	switch {
	case err != nil:
		return nil, err
	case res.Status == http.StatusNotFound:
		// No workflows only if the commit exists: GitHub answers 404 for an
		// unknown ref too.
		var c map[string]any
		if err := r.json(ctx, r.repo+"/commits/"+url.PathEscape(at), &c); err != nil || str(c, "sha") == "" {
			return nil, fmt.Errorf("commit %s: %w", at, err)
		}
		return object(DeployTriggers(nil, branch, at, merge))
	case res.Status != http.StatusOK || json.Unmarshal(res.Body, &listing) != nil:
		return nil, fmt.Errorf("workflow listing answered %d", res.Status)
	case len(listing) >= 1000:
		return object(t.unknown("the workflow directory lists 1000 entries or more")) // GitHub's cap on a listing
	}
	files := map[string][]byte{}
	for _, e := range listing {
		p := str(e, "path")
		if str(e, "type") != "file" || (!strings.HasSuffix(p, ".yml") && !strings.HasSuffix(p, ".yaml")) {
			continue
		}
		if len(files) == MaxWorkflowFiles {
			return object(t.unknown(fmt.Sprintf("more than %d workflow files", MaxWorkflowFiles)))
		}
		var f struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
			Size     int    `json:"size"`
		}
		if err := r.json(ctx, r.repo+"/contents/"+EscapeRef(p)+"?ref="+url.QueryEscape(at), &f); err != nil {
			return nil, err
		}
		if f.Encoding != "base64" || f.Size > MaxWorkflowBytes {
			return object(t.unknown(p + ": not read (size or encoding)"))
		}
		raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
		if err != nil {
			return nil, err
		}
		files[p] = raw
	}
	return object(DeployTriggers(files, branch, at, merge))
}

// object turns triggers into fact members.
func object(t Triggers) (map[string]any, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(b, &out)
}

// Unread is the value of a deploy-trigger fact that could not be read:
// unknown, which holds the action (HR-206).
func Unread(branch, at, why string) map[string]any {
	v, _ := object(Triggers{Branch: branch, At: at}.unknown(why))
	return v
}
