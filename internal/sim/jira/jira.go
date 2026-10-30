// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package jira is a simulated Jira Cloud REST API for tests and demos
// (pantherclaw-sim jira, G0 M20 D254). It answers the calls pc.jira makes:
// projects (search and one by key), issues (read and create), comments and
// transitions, under /rest/api/2 and /rest/api/3, the way Jira does: 401
// without valid Basic credentials, 404 with errorMessages for what the
// caller cannot see, 400 with errors for a bad body, and 429 with
// Retry-After when rate limited. A project of type service_desk is
// customer-visible. It can post Jira-shaped webhooks, signed with an HMAC
// secret, to one URL when an issue changes, and a test can transition an
// issue as a person would in Jira. GET /__sim/state lists what happened,
// for tests. Every response is marked SIMULATED; nothing here reaches
// Jira.
package jira

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Project types. A service_desk project has a customer portal: what is
// written there can reach the organization's customers.
const (
	TypeSoftware    = "software"
	TypeBusiness    = "business"
	TypeServiceDesk = "service_desk"
)

// Transitions every issue offers (one simple workflow).
var Transitions = []Transition{{ID: "11", Name: "To Do"}, {ID: "21", Name: "In Progress"}, {ID: "31", Name: "Done"}}

// maxBody bounds a request body.
const maxBody = 64 << 10

var (
	projectPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,9}$`)
	issuePattern   = regexp.MustCompile(`^([A-Z][A-Z0-9_]{1,9})-([1-9][0-9]{0,8})$`)
)

// Project is one project of the simulated site.
type Project struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Type string `json:"projectTypeKey"`
}

// Transition is a workflow transition.
type Transition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Comment is one comment on an issue.
type Comment struct {
	ID   string `json:"id"`
	Body string `json:"body"`
}

// Issue is one issue with what was done to it.
type Issue struct {
	Key         string    `json:"key"`
	Summary     string    `json:"summary"`
	Description string    `json:"description,omitzero"`
	Type        string    `json:"issuetype"`
	Status      string    `json:"status"`
	Security    string    `json:"security,omitzero"`
	Comments    []Comment `json:"comments,omitzero"`
}

// Faults configures fault injection.
type Faults struct {
	// RateLimit answers the next RateLimit requests with 429 and
	// Retry-After: RetryAfter seconds (default 1).
	RateLimit  int `json:"rate_limit,omitzero"`
	RetryAfter int `json:"retry_after,omitzero"`
	// InvalidAuth answers every request 401 (a revoked API token).
	InvalidAuth bool `json:"invalid_auth,omitzero"`
	// NotFound answers every project and issue call 404 (nothing visible).
	NotFound bool `json:"not_found,omitzero"`
	// DropAnswer performs the next DropAnswer writes and then closes the
	// connection without answering (a lost answer).
	DropAnswer int `json:"drop_answer,omitzero"`
}

// Require is what a request must carry.
type Require struct {
	// Secret is the only Basic credential accepted, base64 of
	// email:api-token as sent; empty accepts any well-formed Basic one.
	Secret string
}

// Webhook is where issue changes are posted, and the secret they are
// signed with (X-Hub-Signature: sha256=<hex HMAC of the body>).
type Webhook struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// Calls counts requests per route, refused ones included.
type Calls map[string]int

// Server is the simulated Jira REST API.
type Server struct {
	require Require
	log     *slog.Logger
	client  *http.Client

	mu       sync.Mutex
	faults   Faults
	projects map[string]Project
	issues   map[string]*Issue
	next     map[string]int
	calls    Calls
	secrets  []string
	webhook  Webhook
	sent     int
	seq      int
}

// New returns a simulator with the given projects and issues.
func New(projects []Project, issues []Issue, f Faults, log *slog.Logger) *Server {
	s := &Server{
		faults: f, log: log, projects: map[string]Project{}, issues: map[string]*Issue{}, next: map[string]int{}, calls: Calls{},
		client: &http.Client{Timeout: 5 * time.Second},
	}
	for _, p := range projects {
		s.projects[p.Key] = p
	}
	for _, is := range issues {
		s.putIssue(is)
	}
	return s
}

func (s *Server) putIssue(is Issue) {
	m := issuePattern.FindStringSubmatch(is.Key)
	if m == nil {
		return
	}
	if is.Status == "" {
		is.Status = Transitions[0].Name
	}
	s.issues[is.Key] = &is
	if n, _ := strconv.Atoi(m[2]); n >= s.next[m[1]] {
		s.next[m[1]] = n + 1
	}
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

// SetProject adds or replaces a project (a test makes one customer-visible).
func (s *Server) SetProject(p Project) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projects[p.Key] = p
}

// SetWebhook sets where issue changes are posted; an empty URL posts none.
func (s *Server) SetWebhook(w Webhook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webhook = w
}

// Issue returns a copy of an issue.
func (s *Server) Issue(key string) (Issue, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	is, ok := s.issues[key]
	if !ok {
		return Issue{}, false
	}
	c := *is
	c.Comments = slices.Clone(is.Comments)
	return c, true
}

// Issues returns a copy of every issue, by key.
func (s *Server) Issues() []Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Issue, 0, len(s.issues))
	for _, k := range slices.Sorted(maps.Keys(s.issues)) {
		c := *s.issues[k]
		c.Comments = slices.Clone(c.Comments)
		out = append(out, c)
	}
	return out
}

// Secrets returns the Basic credential of every authorized request, in
// order.
func (s *Server) Secrets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.secrets)
}

// Calls returns how many requests each route received.
func (s *Server) Calls() Calls {
	s.mu.Lock()
	defer s.mu.Unlock()
	return maps.Clone(s.calls)
}

// Transition moves an issue as a person would in Jira, and posts the
// change to the webhook. It reports whether the issue and transition exist.
func (s *Server) Transition(ctx context.Context, key, id string) bool {
	s.mu.Lock()
	is, ok := s.issues[key]
	i := slices.IndexFunc(Transitions, func(t Transition) bool { return t.ID == id })
	if !ok || i < 0 {
		s.mu.Unlock()
		return false
	}
	is.Status = Transitions[i].Name
	ev := s.event("jira:issue_updated", is)
	s.mu.Unlock()
	s.post(ctx, ev)
	return true
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	return handshake.Wrap("jira", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		switch {
		case r.URL.Path == "/__sim/state" && r.Method == http.MethodGet:
			s.mu.Lock()
			sent := s.sent
			s.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{"issues": s.Issues(), "calls": s.Calls(), "webhooks_sent": sent})
		case r.URL.Path == "/__sim/faults" && r.Method == http.MethodPost:
			var f Faults
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &f) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetFaults(f)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/projects" && r.Method == http.MethodPost:
			var p Project
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &p) != nil || !projectPattern.MatchString(p.Key) || p.Type == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetProject(p)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/webhook" && r.Method == http.MethodPost:
			var h Webhook
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &h) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.SetWebhook(h)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/__sim/transition" && r.Method == http.MethodPost:
			var in struct {
				Issue      string `json:"issue"`
				Transition string `json:"transition"`
			}
			if json.UnmarshalRead(io.LimitReader(r.Body, maxBody), &in) != nil || !s.Transition(r.Context(), in.Issue, in.Transition) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasPrefix(r.URL.Path, "/rest/api/2/"), strings.HasPrefix(r.URL.Path, "/rest/api/3/"):
			s.api(w, r, r.URL.Path[len("/rest/api/2/"):], r.URL.Path[len("/rest/api/")])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// api answers one REST call; version is '2' or '3'.
func (s *Server) api(w http.ResponseWriter, r *http.Request, path string, version byte) {
	segs := strings.Split(path, "/")
	route := r.Method + " " + routeName(segs)
	s.mu.Lock()
	s.calls[route]++
	if s.faults.RateLimit > 0 {
		s.faults.RateLimit--
		after := s.faults.RetryAfter
		if after <= 0 {
			after = 1
		}
		s.mu.Unlock()
		w.Header().Set("Retry-After", strconv.Itoa(after))
		writeJSON(w, http.StatusTooManyRequests, errs("Rate limit exceeded."))
		return
	}
	secret, ok := s.authorized(r)
	if !ok || s.faults.InvalidAuth {
		s.mu.Unlock()
		w.Header().Set("WWW-Authenticate", `Basic realm="simulated"`)
		writeJSON(w, http.StatusUnauthorized, errs("Client must be authenticated to access this resource."))
		return
	}
	s.secrets = append(s.secrets, secret)
	var ev map[string]any
	defer func() {
		s.mu.Unlock()
		if ev != nil {
			s.post(context.WithoutCancel(r.Context()), ev)
		}
	}()
	switch {
	case r.Method == http.MethodGet && len(segs) == 1 && segs[0] == "myself":
		writeJSON(w, http.StatusOK, map[string]any{"accountId": "simulated", "displayName": "PantherClaw (SIMULATED)", "active": true})
	case r.Method == http.MethodGet && len(segs) == 2 && segs[0] == "project" && segs[1] == "search":
		var vals []Project
		if !s.faults.NotFound {
			for _, k := range slices.Sorted(maps.Keys(s.projects)) {
				vals = append(vals, s.projects[k])
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"values": projectsJSON(vals), "total": len(vals), "isLast": true})
	case r.Method == http.MethodGet && len(segs) == 2 && segs[0] == "project":
		p, ok := s.projects[segs[1]]
		if !ok || s.faults.NotFound {
			writeJSON(w, http.StatusNotFound, errs("No project could be found with key '"+segs[1]+"'."))
			return
		}
		writeJSON(w, http.StatusOK, projectJSON(p))
	case r.Method == http.MethodGet && len(segs) == 2 && segs[0] == "issue":
		is, p, ok := s.issue(segs[1])
		if !ok {
			writeJSON(w, http.StatusNotFound, errs("Issue does not exist or you do not have permission to see it."))
			return
		}
		writeJSON(w, http.StatusOK, issueJSON(is, p))
	case r.Method == http.MethodPost && len(segs) == 1 && segs[0] == "issue" && version == '2':
		ev = s.create(w, r)
	case r.Method == http.MethodPost && len(segs) == 3 && segs[0] == "issue" && segs[2] == "comment" && version == '2':
		ev = s.comment(w, r, segs[1])
	case r.Method == http.MethodGet && len(segs) == 3 && segs[0] == "issue" && segs[2] == "transitions":
		if _, _, ok := s.issue(segs[1]); !ok {
			writeJSON(w, http.StatusNotFound, errs("Issue does not exist or you do not have permission to see it."))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"transitions": Transitions})
	case r.Method == http.MethodPost && len(segs) == 3 && segs[0] == "issue" && segs[2] == "transitions":
		ev = s.transition(w, r, segs[1])
	default:
		writeJSON(w, http.StatusNotFound, errs("Null"))
	}
}

// routeName names a call for Calls, its ids replaced.
func routeName(segs []string) string {
	out := slices.Clone(segs)
	for i, seg := range out {
		if projectPattern.MatchString(seg) || issuePattern.MatchString(seg) {
			out[i] = "{key}"
		}
	}
	return strings.Join(out, "/")
}

func (s *Server) authorized(r *http.Request) (string, bool) {
	secret, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Basic ")
	if !ok {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", false
	}
	if user, tok, ok := strings.Cut(string(raw), ":"); !ok || !strings.Contains(user, "@") || tok == "" {
		return "", false
	}
	if s.require.Secret != "" && subtle.ConstantTimeCompare([]byte(secret), []byte(s.require.Secret)) != 1 {
		return "", false
	}
	return secret, true
}

// issue returns a visible issue and its project.
func (s *Server) issue(key string) (*Issue, Project, bool) {
	is, ok := s.issues[key]
	if !ok || s.faults.NotFound {
		return nil, Project{}, false
	}
	p, ok := s.projects[strings.SplitN(key, "-", 2)[0]]
	return is, p, ok
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) map[string]any {
	var in struct {
		Fields struct {
			Project struct {
				Key string `json:"key"`
			} `json:"project"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			IssueType   struct {
				Name string `json:"name"`
			} `json:"issuetype"`
		} `json:"fields"`
	}
	if err := read(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, fieldErr("fields", "The request body could not be read."))
		return nil
	}
	f := in.Fields
	p, ok := s.projects[f.Project.Key]
	switch {
	case !ok || s.faults.NotFound:
		writeJSON(w, http.StatusBadRequest, fieldErr("project", "Specify a valid project ID or key"))
		return nil
	case strings.TrimSpace(f.Summary) == "":
		writeJSON(w, http.StatusBadRequest, fieldErr("summary", "You must specify a summary of the issue."))
		return nil
	case f.IssueType.Name == "":
		writeJSON(w, http.StatusBadRequest, fieldErr("issuetype", "Specify an issue type"))
		return nil
	}
	if s.next[p.Key] == 0 {
		s.next[p.Key] = 1
	}
	key := p.Key + "-" + strconv.Itoa(s.next[p.Key])
	s.next[p.Key]++
	is := &Issue{Key: key, Summary: f.Summary, Description: f.Description, Type: f.IssueType.Name, Status: Transitions[0].Name}
	s.issues[key] = is
	s.log.Info("sim.jira_created", slog.String("issue", key))
	if s.drop(w) {
		return s.event("jira:issue_created", is)
	}
	s.seq++
	writeJSON(w, http.StatusCreated, map[string]any{"id": strconv.Itoa(10000 + s.seq), "key": key, "self": "/rest/api/2/issue/" + key})
	return s.event("jira:issue_created", is)
}

func (s *Server) comment(w http.ResponseWriter, r *http.Request, key string) map[string]any {
	is, _, ok := s.issue(key)
	if !ok {
		writeJSON(w, http.StatusNotFound, errs("Issue does not exist or you do not have permission to see it."))
		return nil
	}
	var in struct {
		Body string `json:"body"`
	}
	if err := read(r, &in); err != nil || strings.TrimSpace(in.Body) == "" {
		writeJSON(w, http.StatusBadRequest, fieldErr("comment", "Comment body can not be empty!"))
		return nil
	}
	s.seq++
	c := Comment{ID: strconv.Itoa(20000 + s.seq), Body: in.Body}
	is.Comments = append(is.Comments, c)
	if s.drop(w) {
		return s.event("comment_created", is)
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": c.ID, "body": c.Body, "self": "/rest/api/2/issue/" + key + "/comment/" + c.ID})
	return s.event("comment_created", is)
}

func (s *Server) transition(w http.ResponseWriter, r *http.Request, key string) map[string]any {
	is, _, ok := s.issue(key)
	if !ok {
		writeJSON(w, http.StatusNotFound, errs("Issue does not exist or you do not have permission to see it."))
		return nil
	}
	var in struct {
		Transition struct {
			ID string `json:"id"`
		} `json:"transition"`
	}
	if err := read(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, fieldErr("transition", "The request body could not be read."))
		return nil
	}
	i := slices.IndexFunc(Transitions, func(t Transition) bool { return t.ID == in.Transition.ID })
	if i < 0 {
		writeJSON(w, http.StatusBadRequest, errs("Transition id '"+in.Transition.ID+"' is not valid for this issue."))
		return nil
	}
	is.Status = Transitions[i].Name
	if s.drop(w) {
		return s.event("jira:issue_updated", is)
	}
	w.WriteHeader(http.StatusNoContent)
	return s.event("jira:issue_updated", is)
}

// drop closes the connection without an answer when a DropAnswer fault is
// pending, and reports whether it did.
func (s *Server) drop(w http.ResponseWriter) bool {
	if s.faults.DropAnswer <= 0 {
		return false
	}
	s.faults.DropAnswer--
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return true
		}
	}
	panic(http.ErrAbortHandler)
}

// event is a webhook body for an issue change, or nil without a webhook.
// The caller holds the lock.
func (s *Server) event(kind string, is *Issue) map[string]any {
	if s.webhook.URL == "" {
		return nil
	}
	p := s.projects[strings.SplitN(is.Key, "-", 2)[0]]
	s.seq++
	return map[string]any{
		"webhookEvent": kind, "timestamp": time.Now().UnixMilli(), "simulated": true, "event_id": strconv.Itoa(30000 + s.seq),
		"issue": issueJSON(is, p),
	}
}

// post sends a webhook body, signed, outside the lock; failures are
// logged, as Jira retries on its own schedule.
func (s *Server) post(ctx context.Context, ev map[string]any) {
	if ev == nil {
		return
	}
	s.mu.Lock()
	h := s.webhook
	s.sent++
	s.mu.Unlock()
	body, err := json.Marshal(ev, json.Deterministic(true))
	if err != nil || h.URL == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if h.Secret != "" {
		mac := hmac.New(sha256.New, []byte(h.Secret))
		mac.Write(body)
		req.Header.Set("X-Hub-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("sim.jira_webhook_failed", slog.String("error", err.Error()))
		return
	}
	_ = resp.Body.Close()
}

func projectJSON(p Project) map[string]any {
	return map[string]any{"id": strconv.Itoa(len(p.Key) * 1000), "key": p.Key, "name": p.Name, "projectTypeKey": p.Type, "simplified": false}
}

func projectsJSON(ps []Project) []map[string]any {
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, projectJSON(p))
	}
	return out
}

func issueJSON(is *Issue, p Project) map[string]any {
	fields := map[string]any{
		"summary": is.Summary, "issuetype": map[string]any{"name": is.Type}, "status": map[string]any{"name": is.Status},
		"project": map[string]any{"key": p.Key, "name": p.Name, "projectTypeKey": p.Type},
		"comment": map[string]any{"total": len(is.Comments)},
	}
	if is.Description != "" {
		fields["description"] = is.Description
	}
	if is.Security != "" {
		fields["security"] = map[string]any{"name": is.Security}
	} else {
		fields["security"] = nil
	}
	return map[string]any{"key": is.Key, "fields": fields}
}

func read(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return http.ErrNotSupported
	}
	return json.UnmarshalRead(io.LimitReader(r.Body, maxBody), v)
}

func errs(msg string) map[string]any {
	return map[string]any{"errorMessages": []string{msg}, "errors": map[string]any{}}
}

func fieldErr(field, msg string) map[string]any {
	return map[string]any{"errorMessages": []string{}, "errors": map[string]any{field: msg}}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
