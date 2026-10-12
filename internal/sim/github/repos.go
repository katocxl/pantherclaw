// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package github

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Settings are the repository settings PATCH /repos/{owner}/{repo} changes.
type Settings struct {
	AllowMergeCommit    bool `json:"allow_merge_commit"`
	AllowSquashMerge    bool `json:"allow_squash_merge"`
	AllowRebaseMerge    bool `json:"allow_rebase_merge"`
	AllowAutoMerge      bool `json:"allow_auto_merge"`
	DeleteBranchOnMerge bool `json:"delete_branch_on_merge"`
}

// Commit is a commit: its files are the whole tree, by path.
type Commit struct {
	SHA     string
	Parents []string
	Files   map[string]string
}

// Repo is a simulated repository.
type Repo struct {
	Owner, Name   string
	DefaultBranch string
	Settings      Settings
	Branches      map[string]string // name to head commit
	Commits       map[string]*Commit
}

func (r *Repo) full() string { return r.Owner + "/" + r.Name }

// CreateRepo creates owner/name with one commit on its default branch and
// returns that commit's SHA.
func (s *Server) CreateRepo(fullName, defaultBranch string, files map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, name, _ := strings.Cut(strings.ToLower(fullName), "/")
	r := &Repo{
		Owner: owner, Name: name, DefaultBranch: defaultBranch, Settings: Settings{AllowMergeCommit: true, AllowSquashMerge: true, AllowRebaseMerge: true},
		Branches: map[string]string{}, Commits: map[string]*Commit{},
	}
	s.repos[r.full()] = r
	sha := s.commit(r, nil, files)
	r.Branches[defaultBranch] = sha
	return sha
}

// Push adds a commit to branch with files changed (an empty value deletes
// a file), creating the branch from the default branch when it does not
// exist, and returns the new head.
func (s *Server) Push(fullName, branch string, files map[string]string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.repos[strings.ToLower(fullName)]
	parent, ok := r.Branches[branch]
	if !ok {
		parent = r.Branches[r.DefaultBranch]
	}
	tree := maps.Clone(r.Commits[parent].Files)
	for p, c := range files {
		if c == "" {
			delete(tree, p)
		} else {
			tree[p] = c
		}
	}
	sha := s.commit(r, []string{parent}, tree)
	s.advance(r, branch, sha, "developer")
	return sha
}

// advance moves branch to a commit pushed by pusher.
func (s *Server) advance(r *Repo, branch, sha, _ string) {
	r.Branches[branch] = sha
}

// Branch returns a branch's head commit ("" when it does not exist).
func (s *Server) Branch(fullName, branch string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.repos[strings.ToLower(fullName)]; r != nil {
		return r.Branches[branch]
	}
	return ""
}

// Files returns the files of a commit.
func (s *Server) Files(fullName, sha string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.repos[strings.ToLower(fullName)]; r != nil && r.Commits[sha] != nil {
		return maps.Clone(r.Commits[sha].Files)
	}
	return nil
}

// RepoSettings returns a repository's default branch and settings.
func (s *Server) RepoSettings(fullName string) (string, Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.repos[strings.ToLower(fullName)]; r != nil {
		return r.DefaultBranch, r.Settings
	}
	return "", Settings{}
}

// commit records a commit; its name is derived from its content and a
// sequence number, so every commit is new.
func (s *Server) commit(r *Repo, parents []string, files map[string]string) string {
	s.seq++
	h := sha256.New()
	fmt.Fprintf(h, "%s %d %v", r.full(), s.seq, parents)
	for _, p := range slices.Sorted(maps.Keys(files)) {
		fmt.Fprintf(h, "\x00%s\x00%s", p, files[p])
	}
	sha := hex.EncodeToString(h.Sum(nil)[:20]) // 40 hex digits, the shape of a git commit name
	r.Commits[sha] = &Commit{SHA: sha, Parents: parents, Files: files}
	return sha
}

// repoRoutes registers the repository endpoints with the permissions
// GitHub documents for each.
func (s *Server) repoRoutes(mux *http.ServeMux) {
	for _, rt := range []route{
		{"GET /repos/{owner}/{repo}", "metadata", "read", s.getRepo},
		{"PATCH /repos/{owner}/{repo}", "administration", "write", s.updateRepo},
		{"GET /repos/{owner}/{repo}/contents/{path...}", "contents", "read", s.contents},
		{"GET /repos/{owner}/{repo}/branches", "contents", "read", s.branches},
		{"POST /repos/{owner}/{repo}/git/refs", "contents", "write", s.createRef},
		{"PUT /repos/{owner}/{repo}/contents/{path...}", "contents", "write", s.putContents},
	} {
		mux.HandleFunc(rt.pattern, s.guard(rt))
	}
}

func (s *Server) getRepo(w http.ResponseWriter, _ *http.Request, r *Repo, _ *Token) int {
	return reply(w, http.StatusOK, map[string]any{
		"id": accountID(r.full()), "name": r.Name, "full_name": r.full(), "owner": map[string]any{"login": r.Owner}, "default_branch": r.DefaultBranch,
		"allow_merge_commit": r.Settings.AllowMergeCommit, "allow_squash_merge": r.Settings.AllowSquashMerge,
		"allow_rebase_merge": r.Settings.AllowRebaseMerge, "allow_auto_merge": r.Settings.AllowAutoMerge,
		"delete_branch_on_merge": r.Settings.DeleteBranchOnMerge, "private": true, "simulated": true,
	})
}

// updateRepo changes the settings it is sent; any other field is refused,
// so a test sees exactly what the gateway sent.
func (s *Server) updateRepo(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	var b struct {
		DefaultBranch       *string `json:"default_branch"`
		AllowMergeCommit    *bool   `json:"allow_merge_commit"`
		AllowSquashMerge    *bool   `json:"allow_squash_merge"`
		AllowRebaseMerge    *bool   `json:"allow_rebase_merge"`
		AllowAutoMerge      *bool   `json:"allow_auto_merge"`
		DeleteBranchOnMerge *bool   `json:"delete_branch_on_merge"`
	}
	if !decode(req, &b) {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	if b.DefaultBranch != nil {
		if _, ok := r.Branches[*b.DefaultBranch]; !ok {
			return fail(w, http.StatusUnprocessableEntity, "Validation Failed")
		}
		r.DefaultBranch = *b.DefaultBranch
	}
	for _, f := range []struct {
		v   *bool
		dst *bool
	}{
		{b.AllowMergeCommit, &r.Settings.AllowMergeCommit},
		{b.AllowSquashMerge, &r.Settings.AllowSquashMerge},
		{b.AllowRebaseMerge, &r.Settings.AllowRebaseMerge},
		{b.AllowAutoMerge, &r.Settings.AllowAutoMerge},
		{b.DeleteBranchOnMerge, &r.Settings.DeleteBranchOnMerge},
	} {
		if f.v != nil {
			*f.dst = *f.v
		}
	}
	return s.getRepo(w, req, r, nil)
}

// decode strictly decodes a request body.
func decode(r *http.Request, v any) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	return err == nil && json.Unmarshal(raw, v, json.RejectUnknownMembers(true)) == nil
}

// resolve returns the commit a ref names: a branch, a full SHA, or the
// default branch when empty.
func (r *Repo) resolve(ref string) *Commit {
	if ref == "" {
		ref = r.DefaultBranch
	}
	if sha, ok := r.Branches[ref]; ok {
		return r.Commits[sha]
	}
	return r.Commits[ref]
}

// contents reads a file (base64, as GitHub encodes it) or lists a
// directory at a ref.
func (s *Server) contents(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	c := r.resolve(req.URL.Query().Get("ref"))
	if c == nil {
		return fail(w, http.StatusNotFound, "No commit found for the ref")
	}
	path := strings.Trim(req.PathValue("path"), "/")
	if body, ok := c.Files[path]; ok {
		sum := sha256.Sum256([]byte(body))
		return reply(w, http.StatusOK, map[string]any{
			"type": "file", "name": path[strings.LastIndexByte(path, '/')+1:], "path": path, "size": len(body),
			"sha": hex.EncodeToString(sum[:20]), "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(body)), "simulated": true,
		})
	}
	seen, entries := map[string]bool{}, []map[string]any{}
	for _, p := range slices.Sorted(maps.Keys(c.Files)) {
		rest, ok := strings.CutPrefix(p, path+"/")
		if path == "" {
			rest, ok = p, true
		}
		if !ok {
			continue
		}
		name, _, dir := strings.Cut(rest, "/")
		if seen[name] {
			continue
		}
		seen[name] = true
		kind := "file"
		if dir {
			kind = "dir"
		}
		entries = append(entries, map[string]any{"type": kind, "name": name, "path": strings.TrimPrefix(path+"/"+name, "/")})
	}
	if len(entries) == 0 {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	return reply(w, http.StatusOK, entries)
}

// branches lists branches with their heads, 30 to a page.
func (s *Server) branches(w http.ResponseWriter, req *http.Request, r *Repo, _ *Token) int {
	page, err := strconv.Atoi(req.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	names := slices.Sorted(maps.Keys(r.Branches))
	from := min((page-1)*30, len(names))
	out := []map[string]any{}
	for _, n := range names[from:min(from+30, len(names))] {
		out = append(out, map[string]any{"name": n, "commit": map[string]any{"sha": r.Branches[n]}})
	}
	return reply(w, http.StatusOK, out)
}

// createRef creates a branch at an existing commit.
func (s *Server) createRef(w http.ResponseWriter, req *http.Request, r *Repo, t *Token) int {
	var b struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	}
	if !decode(req, &b) {
		return fail(w, http.StatusUnprocessableEntity, "Invalid request")
	}
	name, ok := strings.CutPrefix(b.Ref, "refs/heads/")
	switch {
	case !ok || name == "":
		return fail(w, http.StatusUnprocessableEntity, "Reference name is invalid")
	case r.Commits[b.SHA] == nil:
		return fail(w, http.StatusUnprocessableEntity, "Object does not exist")
	case r.Branches[name] != "":
		return fail(w, http.StatusUnprocessableEntity, "Reference already exists")
	}
	s.advance(r, name, b.SHA, actor(t))
	return reply(w, http.StatusCreated, map[string]any{"ref": b.Ref, "object": map[string]any{"type": "commit", "sha": b.SHA}, "simulated": true})
}
