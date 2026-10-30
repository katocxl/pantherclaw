// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package gitlab is a simulated GitLab REST API (v4) for tests and demos
// (pantherclaw-sim gitlab, G0 M20 D254). It answers the calls pc.gitlab
// makes: projects, merge requests with their approvals and head pipeline,
// the merge itself, protected branches and pipelines, under /api/v4, the
// way GitLab does: 401 without a valid access token (Bearer or
// PRIVATE-TOKEN), 404 for what the token cannot see, 405 for a merge
// request that cannot be merged, 409 when the merge names another head,
// and 429 with Retry-After when rate limited. Projects are addressed by
// numeric id. A test can push a new head, set a pipeline's status or
// approve a merge request as a person would in GitLab. GET /__sim/state
// lists what happened. Every response is marked SIMULATED; nothing here
// reaches GitLab.
package gitlab

import (
	"crypto/subtle"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Pipeline statuses GitLab reports.
const (
	PipelineRunning = "running"
	PipelineSuccess = "success"
	PipelineFailed  = "failed"
)

// maxBody bounds a request body.
const maxBody = 64 << 10

var (
	tokenPattern = regexp.MustCompile(`^glpat-[A-Za-z0-9_.-]{20,300}$`)
	shaPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Project is one project of the simulated instance.
type Project struct {
	ID            int    `json:"id"`
	Path          string `json:"path_with_namespace"`
	DefaultBranch string `json:"default_branch"`
	// Protected are the project's protected branches by name.
	Protected map[string]Protection `json:"protected,omitzero"`
	// PipelineMustSucceed refuses a merge whose head pipeline did not
	// succeed (GitLab's "pipelines must succeed").
	PipelineMustSucceed bool `json:"only_allow_merge_if_pipeline_succeeds"`
}

// Protection is one protected branch's rules.
type Protection struct {
	AllowForcePush bool `json:"allow_force_push"`
	// CodeOwnerApproval requires code owners' approval.
	CodeOwnerApproval bool `json:"code_owner_approval_required"`
}

// MergeRequest is one merge request and what was done to it.
type MergeRequest struct {
	Project int    `json:"project_id"`
	IID     int    `json:"iid"`
	Title   string `json:"title"`
	Source  string `json:"source_branch"`
	Target  string `json:"target_branch"`
	SHA     string `json:"sha"`
	// State is opened, merged or closed.
	State     string `json:"state"`
	Author    string `json:"author"`
	Approvers []string
	// ApprovalsRequired is how many approvals the rules require.
	ApprovalsRequired int `json:"approvals_required"`
	// Pipeline is the head pipeline's id, 0 for none.
	Pipeline    int    `json:"head_pipeline_id,omitzero"`
	MergeCommit string `json:"merge_commit_sha,omitzero"`
	Merges      int    `json:"merges"`
}

// Pipeline is one pipeline.
type Pipeline struct {
	ID      int    `json:"id"`
	Project int    `json:"project_id"`
	Ref     string `json:"ref"`
	SHA     string `json:"sha"`
	Status  string `json:"status"`
	Source  string `json:"source"`
}

// Faults configures fault injection.
type Faults struct {
	// RateLimit answers the next RateLimit requests with 429 and
	// Retry-After: RetryAfter seconds (default 1).
	RateLimit  int `json:"rate_limit,omitzero"`
	RetryAfter int `json:"retry_after,omitzero"`
	// InvalidAuth answers every request 401 (a revoked token).
	InvalidAuth bool `json:"invalid_auth,omitzero"`
	// NotFound answers every project call 404 (nothing visible).
	NotFound bool `json:"not_found,omitzero"`
	// DropAnswer performs the next DropAnswer writes and then closes the
	// connection without answering (a lost answer).
	DropAnswer int `json:"drop_answer,omitzero"`
}

// Require is what a request must carry.
type Require struct {
	// Token is the only access token accepted; empty accepts any glpat-
	// token.
	Token string
}

// Calls counts requests per route, refused ones included.
type Calls map[string]int

// Server is the simulated GitLab REST API.
type Server struct {
	require Require
	log     *slog.Logger

	mu        sync.Mutex
	faults    Faults
	projects  map[int]*Project
	mrs       map[string]*MergeRequest
	pipelines map[int]*Pipeline
	calls     Calls
	tokens    []string
	seq       int
}

func mrKey(project, iid int) string { return strconv.Itoa(project) + "!" + strconv.Itoa(iid) }

// New returns a simulator with the given projects, merge requests and
// pipelines.
func New(projects []Project, mrs []MergeRequest, pipelines []Pipeline, f Faults, log *slog.Logger) *Server {
	s := &Server{
		faults: f, log: log, projects: map[int]*Project{}, mrs: map[string]*MergeRequest{}, pipelines: map[int]*Pipeline{}, calls: Calls{},
		seq: 1000,
	}
	for _, p := range projects {
		s.projects[p.ID] = &p
	}
	for _, m := range mrs {
		if m.State == "" {
			m.State = "opened"
		}
		s.mrs[mrKey(m.Project, m.IID)] = &m
	}
	for _, p := range pipelines {
		s.pipelines[p.ID] = &p
		s.seq = max(s.seq, p.ID)
	}
	return s
}

// WithRequire sets what requests must carry, and returns the server.
func (s *Server) WithRequire(r Require) *Server {
	s.require = r
	return s
}

// SetFaults replaces the faults from the next request on.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

// MergeRequest returns a copy of a merge request.
func (s *Server) MergeRequest(project, iid int) (MergeRequest, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mrs[mrKey(project, iid)]
	if !ok {
		return MergeRequest{}, false
	}
	c := *m
	c.Approvers = slices.Clone(m.Approvers)
	return c, true
}

// Push moves a merge request's head to sha, as a push to its source branch
// would, with a new running pipeline; approvals are reset, as GitLab's
// "remove approvals on push" does.
func (s *Server) Push(project, iid int, sha string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mrs[mrKey(project, iid)]
	if !ok || !shaPattern.MatchString(sha) {
		return false
	}
	s.seq++
	s.pipelines[s.seq] = &Pipeline{ID: s.seq, Project: project, Ref: m.Source, SHA: sha, Status: PipelineRunning, Source: "push"}
	m.SHA, m.Pipeline, m.Approvers = sha, s.seq, nil
	return true
}

// SetPipeline sets a pipeline's status (a job finished or failed).
func (s *Server) SetPipeline(id int, status string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pipelines[id]
	if ok {
		p.Status = status
	}
	return ok
}

// Approve adds a person's approval to a merge request.
func (s *Server) Approve(project, iid int, user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.mrs[mrKey(project, iid)]
	if ok && !slices.Contains(m.Approvers, user) {
		m.Approvers = append(m.Approvers, user)
	}
	return ok
}

// Tokens returns the access token of every authorized request, in order.
func (s *Server) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.tokens)
}

// Calls returns how many requests each route received.
func (s *Server) Calls() Calls {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.calls)
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	return handshake.Wrap("gitlab", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		switch {
		case r.URL.Path == "/__sim/state" && r.Method == http.MethodGet:
			s.mu.Lock()
			var mrs []MergeRequest
			for _, k := range slices.Sorted(maps.Keys(s.mrs)) {
				mrs = append(mrs, *s.mrs[k])
			}
			var pipes []Pipeline
			for _, k := range slices.Sorted(maps.Keys(s.pipelines)) {
				pipes = append(pipes, *s.pipelines[k])
			}
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"merge_requests": mrs, "pipelines": pipes, "calls": s.Calls()})
		case r.URL.Path == "/__sim/faults" && r.Method == http.MethodPost:
			var f Faults
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &f) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetFaults(f)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/push" && r.Method == http.MethodPost:
			var in struct {
				Project int    `json:"project"`
				IID     int    `json:"iid"`
				SHA     string `json:"sha"`
			}
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil || !s.Push(in.Project, in.IID, in.SHA) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/pipeline" && r.Method == http.MethodPost:
			var in struct {
				ID     int    `json:"id"`
				Status string `json:"status"`
			}
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil || !s.SetPipeline(in.ID, in.Status) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/approve" && r.Method == http.MethodPost:
			var in struct {
				Project int    `json:"project"`
				IID     int    `json:"iid"`
				User    string `json:"user"`
			}
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil || in.User == "" || !s.Approve(in.Project, in.IID, in.User) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/api/v4/"):
			s.api(w, r, strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v4/"), "/"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// api answers one REST call.
func (s *Server) api(w http.ResponseWriter, r *http.Request, segs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[r.Method+" "+routeName(segs)]++
	if s.faults.RateLimit > 0 {
		s.faults.RateLimit--
		after := s.faults.RetryAfter
		if after <= 0 {
			after = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(after))
		writeJSON(w, http.StatusTooManyRequests, msg("429 Too Many Requests"))
		return
	}
	tok, ok := s.authorized(r)
	if !ok || s.faults.InvalidAuth {
		writeJSON(w, http.StatusUnauthorized, msg("401 Unauthorized"))
		return
	}
	s.tokens = append(s.tokens, tok)
	if r.Method == http.MethodGet && len(segs) == 1 && segs[0] == "user" {
		writeJSON(w, http.StatusOK, map[string]any{"id": 1, "username": "pantherclaw-bot", "bot": true})
		return
	}
	if len(segs) == 1 && segs[0] == "projects" && r.Method == http.MethodGet {
		out := []map[string]any{}
		if !s.faults.NotFound {
			for _, id := range slices.Sorted(maps.Keys(s.projects)) {
				out = append(out, projectJSON(s.projects[id]))
			}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	if len(segs) < 2 || segs[0] != "projects" {
		writeJSON(w, http.StatusNotFound, msg("404 Not Found"))
		return
	}
	id, _ := strconv.Atoi(segs[1])
	p, ok := s.projects[id]
	if !ok || s.faults.NotFound {
		writeJSON(w, http.StatusNotFound, msg("404 Project Not Found"))
		return
	}
	rest := segs[2:]
	switch {
	case r.Method == http.MethodGet && len(rest) == 0:
		writeJSON(w, http.StatusOK, projectJSON(p))
	case r.Method == http.MethodGet && len(rest) == 2 && rest[0] == "protected_branches":
		pr, ok := p.Protected[rest[1]]
		if !ok {
			writeJSON(w, http.StatusNotFound, msg("404 Not found"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"name": rest[1], "allow_force_push": pr.AllowForcePush, "code_owner_approval_required": pr.CodeOwnerApproval,
			"merge_access_levels": []map[string]any{{"access_level": 40, "access_level_description": "Maintainers"}},
			"push_access_levels":  []map[string]any{{"access_level": 40, "access_level_description": "Maintainers"}},
		})
	case r.Method == http.MethodGet && len(rest) == 2 && rest[0] == "pipelines":
		n, _ := strconv.Atoi(rest[1])
		pl, ok := s.pipelines[n]
		if !ok || pl.Project != p.ID {
			writeJSON(w, http.StatusNotFound, msg("404 Not found"))
			return
		}
		writeJSON(w, http.StatusOK, pipelineJSON(pl))
	case len(rest) >= 2 && rest[0] == "merge_requests":
		iid, _ := strconv.Atoi(rest[1])
		m, ok := s.mrs[mrKey(p.ID, iid)]
		if !ok {
			writeJSON(w, http.StatusNotFound, msg("404 Not found"))
			return
		}
		switch {
		case r.Method == http.MethodGet && len(rest) == 2:
			writeJSON(w, http.StatusOK, s.mrJSON(p, m))
		case r.Method == http.MethodGet && len(rest) == 3 && rest[2] == "approvals":
			by := []map[string]any{}
			for _, u := range m.Approvers {
				by = append(by, map[string]any{"user": map[string]any{"username": u}})
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"iid": m.IID, "project_id": p.ID, "approved": len(m.Approvers) >= m.ApprovalsRequired,
				"approvals_required": m.ApprovalsRequired, "approvals_left": max(0, m.ApprovalsRequired-len(m.Approvers)), "approved_by": by,
			})
		case r.Method == http.MethodPut && len(rest) == 3 && rest[2] == "merge":
			s.merge(w, r, p, m)
		default:
			writeJSON(w, http.StatusNotFound, msg("404 Not Found"))
		}
	default:
		writeJSON(w, http.StatusNotFound, msg("404 Not Found"))
	}
}

func (s *Server) merge(w http.ResponseWriter, r *http.Request, p *Project, m *MergeRequest) {
	var in struct {
		SHA    string `json:"sha"`
		Squash bool   `json:"squash"`
	}
	if r.ContentLength != 0 {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil {
			writeJSON(w, http.StatusBadRequest, msg("400 Bad request"))
			return
		}
	}
	pl := s.pipelines[m.Pipeline]
	switch {
	case m.State != "opened":
		writeJSON(w, http.StatusMethodNotAllowed, msg("405 Method Not Allowed"))
		return
	case in.SHA != "" && in.SHA != m.SHA:
		writeJSON(w, http.StatusConflict, msg("SHA does not match HEAD of source branch: "+m.SHA))
		return
	case len(m.Approvers) < m.ApprovalsRequired:
		writeJSON(w, http.StatusMethodNotAllowed, msg("405 Method Not Allowed"))
		return
	case p.PipelineMustSucceed && (pl == nil || pl.SHA != m.SHA || pl.Status != PipelineSuccess):
		writeJSON(w, http.StatusMethodNotAllowed, msg("405 Method Not Allowed"))
		return
	}
	m.State, m.Merges = "merged", m.Merges+1
	m.MergeCommit = fmt.Sprintf("%040x", 0xa000+m.Merges+m.IID*16)
	s.log.Info("sim.gitlab_merged", slog.String("merge_request", mrKey(m.Project, m.IID)))
	if s.faults.DropAnswer > 0 {
		s.faults.DropAnswer--
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler)
	}
	writeJSON(w, http.StatusOK, s.mrJSON(p, m))
}

func (s *Server) authorized(r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		tok = r.Header.Get("PRIVATE-TOKEN")
	}
	if !tokenPattern.MatchString(tok) {
		return "", false
	}
	if s.require.Token != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.require.Token)) != 1 {
		return "", false
	}
	return tok, true
}

// routeName names a call for Calls, its ids replaced.
func routeName(segs []string) string {
	out := slices.Clone(segs)
	for i, seg := range out {
		if _, err := strconv.Atoi(seg); err == nil {
			out[i] = "{id}"
		}
	}
	return strings.Join(out, "/")
}

func (s *Server) mrJSON(p *Project, m *MergeRequest) map[string]any {
	out := map[string]any{
		"iid": m.IID, "project_id": p.ID, "title": m.Title, "state": m.State, "source_branch": m.Source, "target_branch": m.Target,
		"sha": m.SHA, "author": map[string]any{"username": m.Author}, "head_pipeline": nil, "merge_commit_sha": nil,
		"references": map[string]any{"full": p.Path + "!" + strconv.Itoa(m.IID)},
	}
	if pl, ok := s.pipelines[m.Pipeline]; ok {
		out["head_pipeline"] = pipelineJSON(pl)
	}
	if m.MergeCommit != "" {
		out["merge_commit_sha"] = m.MergeCommit
	}
	return out
}

func projectJSON(p *Project) map[string]any {
	return map[string]any{
		"id": p.ID, "path_with_namespace": p.Path, "default_branch": p.DefaultBranch,
		"only_allow_merge_if_pipeline_succeeds": p.PipelineMustSucceed,
	}
}

func pipelineJSON(p *Pipeline) map[string]any {
	return map[string]any{"id": p.ID, "project_id": p.Project, "ref": p.Ref, "sha": p.SHA, "status": p.Status, "source": p.Source}
}

func msg(m string) map[string]any { return map[string]any{"message": m} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
