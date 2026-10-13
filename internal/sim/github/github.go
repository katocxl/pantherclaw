// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package github is a simulated GitHub REST API for tests and demos
// (pantherclaw-sim github, G0 M8 decision 7). It serves the subset the
// pc.github package, the gateway's GitHub App broker and its fact reads
// use: one GitHub App whose installations mint installation tokens scoped
// to repositories and permissions (an App JWT checked as GitHub checks it,
// opaque tokens of GitHub's length, revocation, the installation and the
// repositories it reaches), and repositories with settings, branches,
// commits and files, written one commit at a time under GitHub's rule that
// a workflow file needs the workflows permission; and what the gateway
// reads as facts: branch rules, check runs, workflows, environments, a pull
// request's commits and files, who pushed which ref, and deployments that a
// push starts and that settle after a delay. Faults make the token endpoint
// fail, stall or grant wider than asked, and a merge lose its answer. Every
// request is authenticated, checked against the permission GitHub documents
// for its endpoint, and recorded with the scope of the token it used, so
// tests can assert who did what with which token. Every response is marked
// SIMULATED.
package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Permission levels, from the weakest.
var levels = []string{"read", "write", "admin"}

// covers reports whether the granted level is at least the needed one.
func covers(granted, needed string) bool {
	g, n := slices.Index(levels, granted), slices.Index(levels, needed)
	return g >= 0 && n >= 0 && g >= n
}

// Installation is an installation of the App on one account, with the
// repositories it may reach and the permissions the owner granted.
type Installation struct {
	ID          int64
	Account     string
	Repos       []string // repository names on the account
	Permissions map[string]string
}

// Token is a credential the simulator accepts.
type Token struct {
	value string
	// Installation is the installation that minted it (0 for a personal
	// access token added with AddToken).
	Installation int64
	// User is the person a personal access token acts as.
	User        string
	Repos       []string // full names
	Permissions map[string]string
	Expires     time.Time
	Revoked     bool
	// Uses counts the requests made with it.
	Uses int
}

// Fingerprint identifies a token in logs and assertions without its value.
func Fingerprint(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:8])
}

// Request is one request the simulator answered, with the scope of the
// token it carried.
type Request struct {
	Method, Path string
	Status       int
	// Token is the token's fingerprint ("" without one).
	Token        string
	Installation int64
	User         string
	Repos        []string
	Permissions  map[string]string
	Write        bool
}

// AppJWT is an App JWT the simulator accepted.
type AppJWT struct {
	Issuer            string
	IssuedAt, Expires time.Time
}

// Server is the simulated GitHub API.
type Server struct {
	log *slog.Logger
	now func() time.Time

	mu       sync.Mutex
	appID    int64
	clientID string
	appKey   *rsa.PublicKey
	installs map[int64]*Installation
	tokens   map[string]*Token
	repos    map[string]*Repo
	requests []Request
	jwts     []AppJWT
	seq      int64
	faults   Faults
	// orgApps are other Apps installed on an organization, by its login.
	orgApps map[string][]OrgApp
	// perPage caps a page of a paged list below GitHub's 100 (tests).
	perPage int
}

// New returns a simulator with no App, installation or repository.
func New(log *slog.Logger) *Server {
	return &Server{
		log: log, now: time.Now, installs: map[int64]*Installation{}, tokens: map[string]*Token{}, repos: map[string]*Repo{},
		orgApps: map[string][]OrgApp{},
	}
}

// WithClock replaces the simulator's clock (tests), and returns it.
func (s *Server) WithClock(now func() time.Time) *Server {
	s.now = now
	return s
}

// RegisterApp sets the App whose JWTs mint installation tokens: its id,
// client id and public key.
func (s *Server) RegisterApp(id int64, clientID string, key *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appID, s.clientID, s.appKey = id, clientID, key
}

// Install installs the App on an account.
func (s *Server) Install(in Installation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in.Account = strings.ToLower(in.Account)
	in.Permissions = maps.Clone(in.Permissions)
	s.installs[in.ID] = &in
}

// AddToken accepts a personal access token acting as user on repos (full
// names) with permissions: the kind of credential an agent might find.
func (s *Server) AddToken(value, user string, repos []string, permissions map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[value] = &Token{value: value, User: user, Repos: lower(repos), Permissions: maps.Clone(permissions), Expires: s.now().Add(24 * time.Hour)}
}

// Requests returns every request answered so far, in order.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// AppJWTs returns the App JWTs accepted so far, in order.
func (s *Server) AppJWTs() []AppJWT {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.jwts)
}

// Tokens returns the tokens minted for installations, in no order, without
// their values.
func (s *Server) Tokens() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Token
	for _, t := range s.tokens {
		if t.Installation != 0 {
			c := *t
			c.value = ""
			out = append(out, c)
		}
	}
	return out
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", s.accessToken)
	mux.HandleFunc("DELETE /installation/token", s.revoke)
	mux.HandleFunc("GET /app/installations/{id}", s.installation)
	mux.HandleFunc("GET /installation/repositories", s.installationRepositories)
	mux.HandleFunc("GET /orgs/{org}/installations", s.orgInstallations)
	s.repoRoutes(mux)
	s.pullRoutes(mux)
	s.factRoutes(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		mux.ServeHTTP(w, r)
	})
}

// route is one repository endpoint and the App permission GitHub documents
// for it.
type route struct {
	pattern    string
	permission string
	level      string
	handle     func(w http.ResponseWriter, r *http.Request, repo *Repo, t *Token) int
}

// guard authenticates a repository request, resolves the repository within
// the token's reach (404 otherwise, as GitHub answers), checks the
// endpoint's permission (403) and records the request.
func (s *Server) guard(rt route) http.HandlerFunc {
	write := rt.level != "read"
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		rec := Request{Method: r.Method, Path: r.URL.Path, Write: write}
		// Recorded even when a fault drops the answer.
		defer func() { s.requests = append(s.requests, rec) }()
		rec.Status = s.serveRepo(w, r, rt, &rec)
	}
}

func (s *Server) serveRepo(w http.ResponseWriter, r *http.Request, rt route, rec *Request) int {
	t, status := s.authenticate(r)
	if t == nil {
		return fail(w, status, "Bad credentials")
	}
	t.Uses++
	rec.Token, rec.Installation, rec.User = Fingerprint(t.value), t.Installation, t.User
	rec.Repos, rec.Permissions = slices.Clone(t.Repos), maps.Clone(t.Permissions)
	full := strings.ToLower(r.PathValue("owner") + "/" + r.PathValue("repo"))
	repo := s.repos[full]
	if repo == nil || !slices.Contains(t.Repos, full) {
		return fail(w, http.StatusNotFound, "Not Found")
	}
	granted := t.Permissions[rt.permission]
	if rt.permission == "metadata" && len(t.Permissions) > 0 {
		granted = "read" // every token may read metadata
	}
	if !covers(granted, rt.level) {
		return fail(w, http.StatusForbidden, "Resource not accessible by integration")
	}
	return rt.handle(w, r, repo, t)
}

// authenticate returns the live token a request carries (Bearer or token
// scheme), or nil and 401.
func (s *Server) authenticate(r *http.Request) (*Token, int) {
	h := r.Header.Get("Authorization")
	v, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		v, ok = strings.CutPrefix(h, "token ")
	}
	t := s.tokens[v]
	if !ok || t == nil || t.Revoked || !s.now().Before(t.Expires) {
		return nil, http.StatusUnauthorized
	}
	return t, 0
}

// actor is who a token acts as: the person of a personal access token, or
// the App's bot.
func actor(t *Token) string {
	if t.User != "" {
		return t.User
	}
	return "pantherclaw-sim[bot]"
}

// account is a user object as GitHub answers it: login, id and type,
// "Bot" for an App's [bot] account and "User" otherwise; null for "",
// an email linked to no account.
func account(login string) any {
	if login == "" {
		return nil
	}
	typ := "User"
	if strings.HasSuffix(login, "[bot]") {
		typ = "Bot"
	}
	return map[string]any{"login": login, "id": accountID(login), "type": typ}
}

// SetPageSize caps every page of a paged list at n items (n > 0), below
// GitHub's maximum of 100, so tests can make a list run past one page.
func (s *Server) SetPageSize(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perPage = n
}

// paged answers the page of items that per_page (30 by default, at most
// 100) and page ask for, as GitHub pages a list, and sets a Link header
// naming the next and last pages while there are more.
func (s *Server) paged(w http.ResponseWriter, req *http.Request, items []map[string]any) []map[string]any {
	q := req.URL.Query()
	per := 30
	if n, err := strconv.Atoi(q.Get("per_page")); err == nil && n > 0 {
		per = min(n, 100)
	}
	if s.perPage > 0 {
		per = min(per, s.perPage)
	}
	page := 1
	if n, err := strconv.Atoi(q.Get("page")); err == nil && n > 0 {
		page = n
	}
	last := max((len(items)+per-1)/per, 1)
	if page < last {
		link := func(p int) string {
			u := url.URL{Scheme: "http", Host: req.Host, Path: req.URL.Path}
			v := maps.Clone(q)
			v.Set("page", strconv.Itoa(p))
			u.RawQuery = v.Encode()
			return "<" + u.String() + ">"
		}
		w.Header().Set("Link", link(page+1)+`; rel="next", `+link(last)+`; rel="last"`)
	}
	from := min((page-1)*per, len(items))
	return items[from:min(from+per, len(items))]
}

// fail answers an error as GitHub does and returns the status.
func fail(w http.ResponseWriter, status int, message string) int {
	return reply(w, status, map[string]any{"message": message, "documentation_url": "https://docs.github.com/rest", "simulated": true})
}

// reply writes a JSON answer and returns the status.
func reply(w http.ResponseWriter, status int, v any) int {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
	return status
}

// randomToken returns an opaque installation token shaped like GitHub's
// stateless ones: ghs_ and 516 characters, 520 in all.
func randomToken() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 516)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "ghs_" + string(b)
}
