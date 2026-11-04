// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package model is the fake model provider for tests and demos
// (pantherclaw-sim model, G0 M29 D826): it speaks the request, answer and
// stream shapes of the Anthropic Messages API (with count_tokens and models)
// and of the OpenAI Chat Completions and Responses APIs (with models), so the
// gateway's model connections, the range and the end-to-end tests never spend
// a real token (HR-699).
//
// It is written apart from the gateway's parser on purpose and never imports
// internal/modelapi: it is the independent check of it (G0 M29 D810).
//
// Every answer carries the header Simulated: true and every text it writes
// starts with SIMULATED. The model id picks the behavior: any id answers
// "SIMULATED reply."; sim-max uses the whole max-tokens field; sim-cut cuts
// the answer after its first delta (or half a body); sim-error answers
// Anthropic 529 or OpenAI 503; sim-no-usage leaves the usage chunk out of an
// OpenAI chat stream; sim-tool calls the tool sim_tool. The simulator keeps
// counts, the last accepted key and the sha256 of the last body, never a
// body.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Kind is the simulator's handshake kind (G0 M29 D826).
const Kind = "model"

// DefaultKey is the key the simulator accepts unless told another.
const DefaultKey = "sim-model-key"

// Model ids that pick a behavior (G0 M29 D826). Any other id answers the
// default reply.
const (
	ModelDefault  = "sim-model"
	ModelMax      = "sim-max"
	ModelCut      = "sim-cut"
	ModelError    = "sim-error"
	ModelNoUsage  = "sim-no-usage"
	ModelTool     = "sim-tool"
	ToolName      = "sim_tool"
	Reply         = "SIMULATED reply."
	ToolReply     = "SIMULATED tool call."
	defaultOutput = 8
)

// models is what GET /v1/models lists.
var models = []string{ModelDefault, ModelMax, ModelCut, ModelError, ModelNoUsage, ModelTool}

// maxBody bounds a request body: twice the gateway's 16 MiB limit, so a body
// the gateway should have refused still reaches the simulator's counts.
const maxBody = 32 << 20

// Operations counted in Stats.Calls.
const (
	OpMessages    = "messages"
	OpCountTokens = "count_tokens"
	OpChat        = "chat"
	OpResponses   = "responses"
	OpModels      = "models"
)

// Faults configures fault injection (POST /__sim/faults).
type Faults struct {
	// StreamDelayMS waits this long before each stream event.
	StreamDelayMS int `json:"stream_delay_ms,omitzero"`
	// Status answers every model call with this HTTP status, in the API's
	// error shape (429, 503 and 529 carry Retry-After: 1).
	Status int `json:"status,omitzero"`
}

// Stats counts what was asked (GET /__sim/stats).
type Stats struct {
	// Requests counts every request to an API route, authorized or not.
	Requests int `json:"requests"`
	// Unauthorized counts requests refused 401.
	Unauthorized int `json:"unauthorized"`
	// Calls counts authorized requests by operation.
	Calls map[string]int `json:"calls"`
	// LastKey is the last key accepted.
	LastKey string `json:"last_key,omitzero"`
	// LastBodySHA256 is the hex sha256 of the last authorized request body.
	LastBodySHA256 string `json:"last_body_sha256,omitzero"`
	// LastModel is the model id of the last authorized call.
	LastModel string `json:"last_model,omitzero"`
}

// Server is the fake model provider.
type Server struct {
	key   string
	limit int64
	log   *slog.Logger

	mu        sync.Mutex
	faults    Faults
	stats     Stats
	presented map[[sha256.Size]byte]bool
	seq       int
}

// New returns a simulator that accepts key ("" means DefaultKey).
func New(key string, f Faults, log *slog.Logger) *Server {
	if key == "" {
		key = DefaultKey
	}
	return &Server{key: key, limit: maxBody, log: log, faults: f, stats: Stats{Calls: map[string]int{}}, presented: map[[sha256.Size]byte]bool{}}
}

// SetFaults replaces the faults from the next request on.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

// Stats returns a copy of the counts.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.stats
	c.Calls = make(map[string]int, len(s.stats.Calls))
	for k, v := range s.stats.Calls {
		c.Calls[k] = v
	}
	return c
}

// Presented reports whether any request ever carried key as its credential
// (accepted or not). Only hashes are kept.
func (s *Server) Presented(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.presented[sha256.Sum256([]byte(key))]
}

// api is the shape a route answers in.
type api int

const (
	apiAnthropic api = iota
	apiOpenAI
)

// shapeOf is the shape of a route both providers serve: Anthropic when the
// request sends anthropic-version, else OpenAI (G0 M29 D826).
func shapeOf(r *http.Request) api {
	if r.Header.Get("Anthropic-Version") != "" {
		return apiAnthropic
	}
	return apiOpenAI
}

// Handler serves the simulator.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/messages", s.authed(OpMessages, fixed(apiAnthropic), s.messages))
	mux.HandleFunc("POST /v1/messages/count_tokens", s.authed(OpCountTokens, fixed(apiAnthropic), s.countTokens))
	mux.HandleFunc("POST /v1/chat/completions", s.authed(OpChat, fixed(apiOpenAI), s.chat))
	mux.HandleFunc("POST /v1/responses", s.authed(OpResponses, fixed(apiOpenAI), s.responses))
	mux.HandleFunc("GET /v1/models", s.authed(OpModels, shapeOf, s.listModels))
	mux.HandleFunc("GET /v1/models/{id}", s.authed(OpModels, shapeOf, s.getModel))
	mux.HandleFunc("GET /__sim/stats", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Stats()) })
	mux.HandleFunc("POST /__sim/faults", func(w http.ResponseWriter, r *http.Request) {
		var f Faults
		if json.UnmarshalRead(io.LimitReader(r.Body, 64<<10), &f) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.SetFaults(f)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, shapeOf(r), http.StatusNotFound, "SIMULATED: no such route")
	})
	return handshake.Wrap(Kind, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		mux.ServeHTTP(w, r)
	}))
}

func fixed(a api) func(*http.Request) api { return func(*http.Request) api { return a } }

// call is one authorized request.
type call struct {
	shape api
	body  []byte
	id    int
}

func (s *Server) authed(op string, shape func(*http.Request) api, next func(http.ResponseWriter, *http.Request, call)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := shape(r)
		creds := credentials(r)
		s.mu.Lock()
		s.stats.Requests++
		ok := false
		for _, c := range creds {
			s.presented[sha256.Sum256([]byte(c))] = true
			ok = ok || c == s.key
		}
		if !ok {
			s.stats.Unauthorized++
		}
		s.mu.Unlock()
		if !ok {
			apiError(w, a, http.StatusUnauthorized, "SIMULATED: invalid key")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.limit))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				apiError(w, a, http.StatusRequestEntityTooLarge, "SIMULATED: request too large")
				return
			}
			apiError(w, a, http.StatusBadRequest, "SIMULATED: unreadable body")
			return
		}
		sum := sha256.Sum256(body)
		s.mu.Lock()
		s.stats.Calls[op]++
		s.stats.LastKey = s.key
		s.stats.LastBodySHA256 = hex.EncodeToString(sum[:])
		s.seq++
		c := call{shape: a, body: body, id: s.seq}
		f := s.faults
		s.mu.Unlock()
		s.log.InfoContext(r.Context(), "sim.model_call", slog.String("operation", op), slog.Int("bytes", len(body)))
		if f.Status != 0 && op != OpModels {
			if f.Status == http.StatusTooManyRequests || f.Status == http.StatusServiceUnavailable || f.Status == 529 {
				w.Header().Set("Retry-After", "1")
			}
			apiError(w, a, f.Status, "SIMULATED: fault status")
			return
		}
		next(w, r, c)
	}
}

// credentials are the values of the three headers a key may arrive in.
func credentials(r *http.Request) []string {
	var out []string
	if v := r.Header.Get("X-Api-Key"); v != "" {
		out = append(out, v)
	}
	if v := r.Header.Get("Api-Key"); v != "" {
		out = append(out, v)
	}
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && v != "" {
		out = append(out, v)
	}
	return out
}

// noteModel records the model id of a call.
func (s *Server) noteModel(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.LastModel = m
}

func (s *Server) delay() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Duration(s.faults.StreamDelayMS) * time.Millisecond
}

// inputTokens is the simulated input count: ⌈body bytes / 4⌉ (G0 M29 D826).
func inputTokens(body []byte) int64 { return (int64(len(body)) + 3) / 4 }

// outputTokens is the simulated output count: min(max, 8), or the whole
// max-tokens field for sim-max; max 0 means the request set none.
func outputTokens(model string, maxTokens int64) int64 {
	switch {
	case maxTokens <= 0:
		return defaultOutput
	case model == ModelMax:
		return maxTokens
	default:
		return min(maxTokens, defaultOutput)
	}
}

// listModels answers GET /v1/models in the request's shape.
func (s *Server) listModels(w http.ResponseWriter, _ *http.Request, c call) {
	if c.shape == apiAnthropic {
		data := make([]any, 0, len(models))
		for _, m := range models {
			data = append(data, anthropicModel(m))
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": data, "has_more": false, "first_id": models[0], "last_id": models[len(models)-1]})
		return
	}
	data := make([]any, 0, len(models))
	for _, m := range models {
		data = append(data, openaiModel(m))
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// getModel answers GET /v1/models/{id}; any id is a simulated model.
func (s *Server) getModel(w http.ResponseWriter, r *http.Request, c call) {
	id := r.PathValue("id")
	if c.shape == apiAnthropic {
		writeJSON(w, http.StatusOK, anthropicModel(id))
		return
	}
	writeJSON(w, http.StatusOK, openaiModel(id))
}

func anthropicModel(id string) map[string]any {
	return map[string]any{"type": "model", "id": id, "display_name": "SIMULATED " + id, "created_at": "2026-01-01T00:00:00Z"}
}

func openaiModel(id string) map[string]any {
	return map[string]any{"id": id, "object": "model", "created": int64(1767225600), "owned_by": "pantherclaw-sim"}
}

// apiError answers status in the API's error shape.
func apiError(w http.ResponseWriter, a api, status int, msg string) {
	if a == apiAnthropic {
		t := "api_error"
		switch status {
		case http.StatusBadRequest:
			t = "invalid_request_error"
		case http.StatusUnauthorized:
			t = "authentication_error"
		case http.StatusForbidden:
			t = "permission_error"
		case http.StatusNotFound:
			t = "not_found_error"
		case http.StatusRequestEntityTooLarge:
			t = "request_too_large"
		case http.StatusTooManyRequests:
			t = "rate_limit_error"
		case 529:
			t = "overloaded_error"
		}
		w.Header().Set("Request-Id", "req_sim")
		writeJSON(w, status, map[string]any{"type": "error", "error": map[string]any{"type": t, "message": msg}})
		return
	}
	t, code := "server_error", any(nil)
	switch {
	case status == http.StatusUnauthorized:
		t, code = "invalid_request_error", "invalid_api_key"
	case status == http.StatusTooManyRequests:
		t, code = "rate_limit_exceeded", "rate_limit_exceeded"
	case status < 500:
		t = "invalid_request_error"
	}
	w.Header().Set("X-Request-Id", "req_sim")
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "type": t, "param": nil, "code": code}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeCut writes half of v's encoding under the full Content-Length, then
// drops the connection (sim-cut on a non-stream answer).
func writeCut(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b[:len(b)/2])
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	panic(http.ErrAbortHandler)
}

// event is one server-sent event. name is empty for OpenAI chat chunks;
// data is a JSON value or the raw string [DONE]. delta marks a content delta,
// after the first of which sim-cut drops the stream.
type event struct {
	name  string
	data  any
	delta bool
}

// stream writes events as text/event-stream, flushing each, and drops the
// connection after the first delta when cut is set.
func (s *Server) stream(w http.ResponseWriter, r *http.Request, events []event, cut bool) {
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	d := s.delay()
	for _, ev := range events {
		if d > 0 {
			t := time.NewTimer(d)
			select {
			case <-r.Context().Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		var data []byte
		if raw, ok := ev.data.(string); ok {
			data = []byte(raw)
		} else {
			b, err := json.Marshal(ev.data, json.Deterministic(true))
			if err != nil {
				panic(http.ErrAbortHandler)
			}
			data = b
		}
		var b strings.Builder
		if ev.name != "" {
			b.WriteString("event: " + ev.name + "\n")
		}
		b.WriteString("data: ")
		b.Write(data)
		b.WriteString("\n\n")
		if _, err := io.WriteString(w, b.String()); err != nil {
			return
		}
		if fl != nil {
			fl.Flush()
		}
		if cut && ev.delta {
			panic(http.ErrAbortHandler)
		}
	}
}
