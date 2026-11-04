// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package salesforce is a simulated Salesforce org for tests and demos
// (pantherclaw-sim salesforce, G0 M31 D960). It serves the two parts the
// pc.salesforce package talks to:
//
//   - the OAuth 2.0 token endpoint, POST /services/oauth2/token, which
//     issues an access token for the client-credentials grant (the gateway
//     mints one per dispatch for an oauth_client credential, D951);
//   - the REST API under /services/data/v61.0: a record read and update,
//     a SOQL query, a report run and the org's limits (the connection
//     test).
//
// Every API request must carry a token this simulator issued and that has
// not expired. Records hold SYNTHETIC data only. GET /__sim/stats counts
// requests per route, issued tokens and updates, for tests. Every response
// is marked SIMULATED; nothing here reaches Salesforce.
package salesforce

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

const simKind = "salesforce"

// Simulated identities.
const (
	// APIVersion is the only REST API version served.
	APIVersion = "v61.0"
	// AccountID is a simulated Account record.
	AccountID = "001SIM000000001AAA"
	// ContactID is a simulated Contact record.
	ContactID = "003SIM000000001AAA"
	// ReportID is a simulated report.
	ReportID = "00OSIM000000001AAA"
	// TokenLifetime is how long an issued token is accepted.
	TokenLifetime = time.Hour
)

// maxBody bounds a request body.
const maxBody = 64 << 10

var (
	sobjectPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,79}$`)
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9]{15,18}$`)
	fromPattern    = regexp.MustCompile(`(?i)\bfrom\s+([A-Za-z][A-Za-z0-9_]{0,79})`)
)

// Faults configures fault injection.
type Faults struct {
	// InvalidClient refuses every token request: 400 invalid_client.
	InvalidClient bool `json:"invalid_client,omitzero"`
	// ExpireTokens treats every issued token as expired: 401.
	ExpireTokens bool `json:"expire_tokens,omitzero"`
	// RateLimit answers the next RateLimit API requests with 403
	// REQUEST_LIMIT_EXCEEDED, as Salesforce does.
	RateLimit int `json:"rate_limit,omitzero"`
}

// Require is what a token request must carry.
type Require struct {
	// ClientID and ClientSecret are the only client accepted; an empty
	// ClientID accepts any.
	ClientID, ClientSecret string
}

// Stats counts what was asked.
type Stats struct {
	Calls   map[string]int `json:"calls"`
	Issued  int            `json:"issued"`
	Updates int            `json:"updates"`
}

// Server is the simulated org.
type Server struct {
	require Require
	log     *slog.Logger

	mu      sync.Mutex
	faults  Faults
	records map[string]map[string]map[string]any // sobject → id → fields
	calls   map[string]int
	issued  map[string]time.Time
	updates int
	now     func() time.Time
}

// New returns a simulator with the default SYNTHETIC records.
func New(f Faults, log *slog.Logger) *Server {
	s := &Server{faults: f, log: log, calls: map[string]int{}, issued: map[string]time.Time{}, now: time.Now}
	s.records = map[string]map[string]map[string]any{
		"Account": {AccountID: {"Id": AccountID, "Name": "SYNTHETIC Acme Corp", "Industry": "Manufacturing", "AnnualRevenue": 1000000}},
		"Contact": {ContactID: {
			"Id": ContactID, "AccountId": AccountID, "FirstName": "Synthetic", "LastName": "Person",
			"Email": "synthetic.person@example.test", "Phone": "+1-555-0100",
		}},
	}
	return s
}

// WithRequire sets what token requests must carry, and returns the server.
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

// SetClock replaces the clock tokens expire by.
func (s *Server) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Record returns a copy of one record's fields.
func (s *Server) Record(sobject, id string) (map[string]any, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[sobject][id]
	return maps.Clone(r), ok
}

// Stats returns the counts.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Calls: maps.Clone(s.calls), Issued: len(s.issued), Updates: s.updates}
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	base := "/services/data/" + APIVersion
	mux := http.NewServeMux()
	mux.HandleFunc("POST /services/oauth2/token", s.token)
	mux.HandleFunc("GET "+base+"/limits", s.authed("limits", s.limits))
	mux.HandleFunc("GET "+base+"/sobjects/{sobject}/{id}", s.authed("record.get", s.get))
	mux.HandleFunc("PATCH "+base+"/sobjects/{sobject}/{id}", s.authed("record.update", s.update))
	mux.HandleFunc("GET "+base+"/query", s.authed("query", s.query))
	mux.HandleFunc("GET "+base+"/analytics/reports/{report}", s.authed("report.run", s.report))
	mux.HandleFunc("GET /__sim/stats", func(w http.ResponseWriter, _ *http.Request) { write(w, http.StatusOK, s.Stats()) })
	return handshake.Wrap(simKind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		mux.ServeHTTP(w, r)
	}))
}

// token answers the client-credentials grant (RFC 6749 §4.4).
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		write(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "SIMULATED: unreadable form"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls["token"]++
	if r.PostForm.Get("grant_type") != "client_credentials" {
		write(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type", "error_description": "SIMULATED: grant type not supported"})
		return
	}
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if s.faults.InvalidClient || id == "" || secret == "" || (s.require.ClientID != "" &&
		(subtle.ConstantTimeCompare([]byte(id), []byte(s.require.ClientID)) != 1 ||
			subtle.ConstantTimeCompare([]byte(secret), []byte(s.require.ClientSecret)) != 1)) {
		write(w, http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "SIMULATED: invalid client credentials"})
		return
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	tok := "00DSIM!" + hex.EncodeToString(b)
	s.issued[tok] = s.now().Add(TokenLifetime)
	write(w, http.StatusOK, map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int(TokenLifetime.Seconds()),
		"instance_url": "https://" + r.Host, "issued_at": s.now().UnixMilli(),
	})
}

// authed checks the bearer token and counts the route.
func (s *Server) authed(route string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.calls[route]++
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		exp, known := s.issued[tok]
		expired := s.faults.ExpireTokens || !s.now().Before(exp)
		limited := s.faults.RateLimit > 0
		if limited {
			s.faults.RateLimit--
		}
		s.mu.Unlock()
		switch {
		case !ok || !known || expired:
			write(w, http.StatusUnauthorized, []map[string]string{{"errorCode": "INVALID_SESSION_ID", "message": "SIMULATED: Session expired or invalid"}})
			return
		case limited:
			write(w, http.StatusForbidden, []map[string]string{{"errorCode": "REQUEST_LIMIT_EXCEEDED", "message": "SIMULATED: request limit exceeded"}})
			return
		}
		next(w, r)
	}
}

func (s *Server) limits(w http.ResponseWriter, _ *http.Request) {
	write(w, http.StatusOK, map[string]any{"DailyApiRequests": map[string]int{"Max": 15000, "Remaining": 14999}})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	sobject, id := r.PathValue("sobject"), r.PathValue("id")
	if !sobjectPattern.MatchString(sobject) || !idPattern.MatchString(id) {
		write(w, http.StatusBadRequest, []map[string]string{{"errorCode": "MALFORMED_ID", "message": "SIMULATED: malformed id"}})
		return
	}
	s.mu.Lock()
	rec, ok := s.records[sobject][id]
	rec = maps.Clone(rec)
	s.mu.Unlock()
	if !ok {
		write(w, http.StatusNotFound, []map[string]string{{"errorCode": "NOT_FOUND", "message": "SIMULATED: The requested resource does not exist"}})
		return
	}
	rec["attributes"] = map[string]string{"type": sobject, "url": "/services/data/" + APIVersion + "/sobjects/" + sobject + "/" + id}
	write(w, http.StatusOK, rec)
}

// update merges the body's fields into the record; Id and attributes are
// never written. Salesforce answers a successful update 204.
func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	sobject, id := r.PathValue("sobject"), r.PathValue("id")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	var fields map[string]any
	if err != nil || json.Unmarshal(body, &fields) != nil || fields == nil {
		write(w, http.StatusBadRequest, []map[string]string{{"errorCode": "JSON_PARSER_ERROR", "message": "SIMULATED: the body is not a JSON object"}})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[sobject][id]
	if !ok {
		write(w, http.StatusNotFound, []map[string]string{{"errorCode": "NOT_FOUND", "message": "SIMULATED: The requested resource does not exist"}})
		return
	}
	for _, k := range slices.Sorted(maps.Keys(fields)) {
		if k == "Id" || k == "attributes" {
			write(w, http.StatusBadRequest, []map[string]string{{"errorCode": "INVALID_FIELD_FOR_INSERT_UPDATE", "message": "SIMULATED: field " + k + " is not writable"}})
			return
		}
	}
	maps.Copy(rec, fields)
	s.updates++
	w.WriteHeader(http.StatusNoContent)
}

// query answers every record of the sobject the SOQL's FROM clause names;
// the simulator does not evaluate the rest of the statement.
func (s *Server) query(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	m := fromPattern.FindStringSubmatch(q)
	if q == "" || len(q) > 100_000 || m == nil {
		write(w, http.StatusBadRequest, []map[string]string{{"errorCode": "MALFORMED_QUERY", "message": "SIMULATED: unexpected token"}})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, ok := s.records[m[1]]
	if !ok {
		write(w, http.StatusBadRequest, []map[string]string{{"errorCode": "INVALID_TYPE", "message": "SIMULATED: sObject type is not supported"}})
		return
	}
	out := make([]map[string]any, 0, len(recs))
	for _, id := range slices.Sorted(maps.Keys(recs)) {
		rec := maps.Clone(recs[id])
		rec["attributes"] = map[string]string{"type": m[1], "url": "/services/data/" + APIVersion + "/sobjects/" + m[1] + "/" + id}
		out = append(out, rec)
	}
	write(w, http.StatusOK, map[string]any{"totalSize": len(out), "done": true, "records": out})
}

// report runs the one simulated report synchronously.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("report") != ReportID {
		write(w, http.StatusNotFound, []map[string]string{{"errorCode": "NOT_FOUND", "message": "SIMULATED: report not found"}})
		return
	}
	write(w, http.StatusOK, map[string]any{
		"attributes":     map[string]string{"reportId": ReportID, "reportName": "SYNTHETIC accounts by industry", "type": "Report"},
		"allData":        true,
		"hasDetailRows":  true,
		"reportMetadata": map[string]any{"id": ReportID, "name": "SYNTHETIC accounts by industry", "reportFormat": "TABULAR"},
		"factMap": map[string]any{"T!T": map[string]any{
			"rows":       []map[string]any{{"dataCells": []map[string]any{{"label": "SYNTHETIC Acme Corp", "value": AccountID}, {"label": "Manufacturing", "value": "Manufacturing"}}}},
			"aggregates": []map[string]any{{"label": "1", "value": 1}},
		}},
	})
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
