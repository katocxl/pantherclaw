// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package openapi is a generic simulated target served from an OpenAPI 3
// spec for tests and demos (pantherclaw-sim openapi, G0 M31 D954): every
// operation of the spec answers its first 2xx status with its first JSON
// example, or {} when the spec gives none. Each call is recorded, never
// the credential, and the record is served at /__sim/stats. Every answer is
// marked SIMULATED; nothing here reaches the real API.
package openapi

import (
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	spec "github.com/katocxl/pantherclaw/internal/definitions/openapi"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

const simKind = "openapi"

// Limits on what is recorded.
const (
	maxCalls     = 1000
	maxBodyBytes = 64 << 10
)

// Call is one recorded request: the operation it matched, its method,
// path, query and body (at most 64 KiB), and whether it carried an
// Authorization header, never the header's value.
type Call struct {
	Operation string `json:"operation"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query,omitzero"`
	Body      string `json:"body,omitzero"`
	Auth      bool   `json:"authorization"`
}

// Stats counts what was asked: every request, the ones no operation
// matched, each operation's calls, and the most recent calls in order.
type Stats struct {
	Requests  int            `json:"requests"`
	Unmatched int            `json:"unmatched"`
	ByOp      map[string]int `json:"by_operation"`
	Calls     []Call         `json:"calls"`
}

// Server is the simulated API.
type Server struct {
	ops []spec.Operation
	log *slog.Logger

	mu    sync.Mutex
	stats Stats
}

// New returns a simulator serving the spec's operations.
func New(s *spec.Spec, log *slog.Logger) *Server {
	return &Server{ops: s.Operations, log: log, stats: Stats{ByOp: map[string]int{}, Calls: []Call{}}}
}

// Stats returns a copy of the counts.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.ByOp = make(map[string]int, len(s.stats.ByOp))
	for k, v := range s.stats.ByOp {
		out.ByOp[k] = v
	}
	out.Calls = append([]Call(nil), s.stats.Calls...)
	return out
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	return handshake.Wrap(simKind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		if r.Method == http.MethodGet && r.URL.Path == "/__sim/stats" {
			write(w, http.StatusOK, s.Stats())
			return
		}
		s.serve(w, r)
	}))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	op := s.match(r.Method, r.URL.Path)
	s.mu.Lock()
	s.stats.Requests++
	if op == nil {
		s.stats.Unmatched++
		s.mu.Unlock()
		write(w, http.StatusNotFound, map[string]string{"error": "SIMULATED: no operation of the spec matches"})
		return
	}
	s.stats.ByOp[op.ID]++
	if len(s.stats.Calls) == maxCalls {
		s.stats.Calls = s.stats.Calls[1:]
	}
	s.stats.Calls = append(s.stats.Calls, Call{
		Operation: op.ID, Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: string(body),
		Auth: r.Header.Get("Authorization") != "",
	})
	s.mu.Unlock()
	var answer any = map[string]any{}
	if op.Example != nil {
		answer = op.Example
	}
	write(w, op.Status, answer)
}

// match finds the operation whose method and path template match: a
// literal segment exactly, a {variable} any one non-empty segment.
func (s *Server) match(method, path string) *spec.Operation {
	got := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := range s.ops {
		op := &s.ops[i]
		if op.Method != method {
			continue
		}
		want := strings.Split(strings.TrimPrefix(op.Path, "/"), "/")
		if len(want) != len(got) {
			continue
		}
		ok := true
		for j, seg := range want {
			if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
				ok = got[j] != ""
			} else {
				ok = seg == got[j]
			}
			if !ok {
				break
			}
		}
		if ok {
			return op
		}
	}
	return nil
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}
