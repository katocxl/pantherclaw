// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package snowflake is the fake Snowflake SQL API for tests and demos
// (pantherclaw-sim snowflake, G0 M31 D962): POST /api/v2/statements and
// GET /api/v2/statements/{handle}, behind a key-pair JWT. It never runs
// SQL: it checks the request's shape (a KEYPAIR_JWT bearer whose claims
// have Snowflake's form and an hour at most, with the signature checked
// against a public key when one is given; ? placeholders matching TEXT
// bindings; a timeout of 1 to 60 s; a warehouse, database and schema) and
// answers one row of NULLs per statement, as many columns as the statement
// selects. It keeps counts and the sha256 of the last statement, never a
// binding's value.
package snowflake

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Kind is the simulator's handshake kind.
const Kind = "snowflake"

const maxBody = 1 << 20

// Faults configures fault injection.
type Faults struct {
	// Async answers the first N statements 202 (still running); the poll
	// that follows gets the answer.
	Async int
	// RateLimit answers the first N requests 429.
	RateLimit int
	// Unauthorized answers every request 401 (a removed public key).
	Unauthorized bool
}

// Stats counts what was asked (GET /__sim/stats).
type Stats struct {
	Requests     int `json:"requests"`
	Unauthorized int `json:"unauthorized"`
	Statements   int `json:"statements"`
	Polls        int `json:"polls"`
	// LastStatementSHA256 is the hex sha256 of the last statement text.
	LastStatementSHA256 string `json:"last_statement_sha256,omitzero"`
	LastBindings        int    `json:"last_bindings"`
	LastWarehouse       string `json:"last_warehouse,omitzero"`
	LastSubject         string `json:"last_subject,omitzero"`
}

// Server is the fake SQL API.
type Server struct {
	pub *rsa.PublicKey
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	faults  Faults
	stats   Stats
	pending map[string]int // handle → selected columns
	seq     int
}

// New returns a simulator; pub, when set, is the only key whose JWTs pass.
func New(pub *rsa.PublicKey, f Faults, log *slog.Logger) *Server {
	return &Server{pub: pub, log: log, now: time.Now, faults: f, pending: map[string]int{}}
}

// ParsePublicKey reads a PEM RSA public key (PKIX), as Snowflake takes it.
func ParsePublicKey(b []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("snowflake sim: not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := k.(*rsa.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("snowflake sim: not an RSA public key")
	}
	return pub, nil
}

// Stats returns a copy of the counts.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v2/statements", s.authed(s.statement))
	mux.HandleFunc("GET /api/v2/statements/{handle}", s.authed(s.poll))
	mux.HandleFunc("GET /__sim/stats", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Stats()) })
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		apiError(w, http.StatusNotFound, "390404", "SIMULATED: no such route")
	})
	return handshake.Wrap(Kind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		mux.ServeHTTP(w, r)
	}))
}

var (
	issRe = regexp.MustCompile(`^([A-Z0-9_-]+\.[A-Z0-9_.@$-]+)\.SHA256:[A-Za-z0-9+/]{43}=$`)
	subRe = regexp.MustCompile(`^[A-Z0-9_-]+\.[A-Z0-9_.@$-]+$`)
)

func (s *Server) authed(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.stats.Requests++
		limited := s.faults.RateLimit > 0
		if limited {
			s.faults.RateLimit--
		}
		unauthorized := s.faults.Unauthorized
		s.mu.Unlock()
		if limited {
			apiError(w, http.StatusTooManyRequests, "000629", "SIMULATED: too many requests")
			return
		}
		sub, err := s.checkJWT(r)
		if err != nil || unauthorized {
			s.mu.Lock()
			s.stats.Unauthorized++
			s.mu.Unlock()
			apiError(w, http.StatusUnauthorized, "390144", "SIMULATED: JWT token is invalid")
			return
		}
		s.mu.Lock()
		s.stats.LastSubject = sub
		s.mu.Unlock()
		next(w, r)
	}
}

// checkJWT checks the key-pair JWT's form and, with a public key, its
// signature and fingerprint; it returns the subject.
func (s *Server) checkJWT(r *http.Request) (string, error) {
	if r.Header.Get("X-Snowflake-Authorization-Token-Type") != "KEYPAIR_JWT" {
		return "", errors.New("token type")
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		return "", errors.New("form")
	}
	var head struct {
		Alg string `json:"alg"`
	}
	var claims struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	cb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || json.Unmarshal(hb, &head) != nil || json.Unmarshal(cb, &claims) != nil || head.Alg != "RS256" {
		return "", errors.New("form")
	}
	m := issRe.FindStringSubmatch(claims.Iss)
	now := s.now().Unix()
	if m == nil || !subRe.MatchString(claims.Sub) || m[1] != claims.Sub || claims.Exp <= now || claims.Exp-claims.Iat > 3600 ||
		claims.Iat > now+60 {
		return "", errors.New("claims")
	}
	if s.pub != nil {
		der, err := x509.MarshalPKIXPublicKey(s.pub)
		if err != nil {
			return "", err
		}
		fp := sha256.Sum256(der)
		if !strings.HasSuffix(claims.Iss, ".SHA256:"+base64.StdEncoding.EncodeToString(fp[:])) {
			return "", errors.New("fingerprint")
		}
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if rsa.VerifyPKCS1v15(s.pub, crypto.SHA256, sum[:], sig) != nil {
			return "", errors.New("signature")
		}
	}
	return claims.Sub, nil
}

// request is the part of a statement request the simulator reads.
type request struct {
	Statement string `json:"statement"`
	Timeout   int64  `json:"timeout"`
	Bindings  map[string]struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"bindings"`
	Warehouse string `json:"warehouse"`
	Database  string `json:"database"`
	Schema    string `json:"schema"`
}

var upperIdent = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,62}$`)

func (s *Server) statement(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	var req request
	if err != nil || len(body) > maxBody || json.Unmarshal(body, &req) != nil {
		apiError(w, http.StatusBadRequest, "390142", "SIMULATED: invalid request body")
		return
	}
	switch {
	case !strings.HasPrefix(req.Statement, "SELECT "):
		apiError(w, http.StatusBadRequest, "001003", "SIMULATED: only a SELECT is answered")
		return
	case req.Timeout < 1 || req.Timeout > 60:
		apiError(w, http.StatusBadRequest, "390142", "SIMULATED: timeout must be 1..60 seconds")
		return
	case !upperIdent.MatchString(req.Warehouse) || !upperIdent.MatchString(req.Database) || !upperIdent.MatchString(req.Schema):
		apiError(w, http.StatusBadRequest, "390142", "SIMULATED: warehouse, database and schema are required")
		return
	case strings.Count(req.Statement, "?") != len(req.Bindings):
		apiError(w, http.StatusUnprocessableEntity, "002049", "SIMULATED: bind variable count mismatch")
		return
	}
	for i := 1; i <= len(req.Bindings); i++ {
		b, ok := req.Bindings[fmt.Sprint(i)]
		if !ok || b.Type != "TEXT" {
			apiError(w, http.StatusUnprocessableEntity, "002049", "SIMULATED: bindings are 1..n, each TEXT")
			return
		}
	}
	cols := selectedColumns(req.Statement)
	sum := sha256.Sum256([]byte(req.Statement))
	s.mu.Lock()
	s.stats.Statements++
	s.stats.LastStatementSHA256 = hex.EncodeToString(sum[:])
	s.stats.LastBindings = len(req.Bindings)
	s.stats.LastWarehouse = req.Warehouse
	s.seq++
	handle := fmt.Sprintf("01b0c0d0-0000-4000-8000-%012d", s.seq)
	async := s.faults.Async > 0
	if async {
		s.faults.Async--
		s.pending[handle] = cols
	}
	s.mu.Unlock()
	s.log.InfoContext(r.Context(), "sim.snowflake_statement", slog.Int("bindings", len(req.Bindings)), slog.Int("columns", cols))
	if async {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"code": "333334", "message": "Asynchronous execution in progress.", "statementHandle": handle,
			"statementStatusUrl": "/api/v2/statements/" + handle,
		})
		return
	}
	answer(w, handle, cols)
}

func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("handle")
	s.mu.Lock()
	s.stats.Polls++
	cols, ok := s.pending[handle]
	delete(s.pending, handle)
	s.mu.Unlock()
	if !ok {
		apiError(w, http.StatusNotFound, "390404", "SIMULATED: no such statement")
		return
	}
	answer(w, handle, cols)
}

// selectedColumns counts the statement's value expressions: each the
// gateway writes as LEFT(TO_VARCHAR(…), n).
func selectedColumns(stmt string) int {
	sel, _, _ := strings.Cut(stmt, " FROM ")
	return strings.Count(sel, "LEFT(TO_VARCHAR(")
}

// answer is one row of NULLs, cols wide.
func answer(w http.ResponseWriter, handle string, cols int) {
	rowType := make([]any, cols)
	row := make([]any, cols)
	for i := range rowType {
		rowType[i] = map[string]any{"name": fmt.Sprintf("C%d", i+1), "type": "text", "nullable": true}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": "090001", "message": "Statement executed successfully.", "statementHandle": handle,
		"resultSetMetaData": map[string]any{
			"numRows": 1, "format": "jsonv2", "rowType": rowType, "partitionInfo": []any{map[string]any{"rowCount": 1}},
		},
		"data": []any{row},
	})
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"code": code, "message": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
