// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"slices"
	"strings"
)

// The simulator's reviewed-surface behaviour (G0 M15 D31, D33): it serves
// resources/read for its refunds, payments://refunds/<id>, and, when an
// elicitation is set, answers a 2026-07-28 create_refund without
// inputResponses with an input_required result asking for it; a retry that
// carries inputResponses runs the tool.

// ResourcePrefix is the URI prefix of the simulator's refund resources.
const ResourcePrefix = "payments://refunds/"

// Elicit is the elicitation a 2026-07-28 create_refund asks for.
type Elicit struct {
	// Key is the input request's key ("confirm" when empty).
	Key string
	// Mode is the elicitation's mode: "" (form, the default), "form" or
	// "url".
	Mode string
	// Message is the question.
	Message string
	// Schema is the requested schema; URL is a url-mode request's URL.
	Schema jsontext.Value
	URL    string
	// RequestState, when set, is sent with the request and expected back.
	RequestState string
}

// surface is the simulator's surface state, under Server.mu.
type surface struct {
	elicit   *Elicit
	reads    []string
	answered []jsontext.Value
	states   []string
}

// SetElicit makes create_refund ask for e (nil: never).
func (s *Server) SetElicit(e *Elicit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.surface.elicit = e
}

// ResourceReads are the URIs of every resources/read received, in order.
func (s *Server) ResourceReads() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.surface.reads)
}

// InputResponses are the inputResponses of every retried create_refund,
// in order, with the requestState each carried.
func (s *Server) InputResponses() ([]jsontext.Value, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.surface.answered), slices.Clone(s.surface.states)
}

// readResource answers resources/read: a refund's JSON, or "Resource not
// found".
func (s *Server) readResource(w http.ResponseWriter, m message) {
	var p struct {
		URI string `json:"uri"`
	}
	_ = json.Unmarshal(m.Params, &p)
	s.mu.Lock()
	s.surface.reads = append(s.surface.reads, p.URI)
	id, ok := strings.CutPrefix(p.URI, ResourcePrefix)
	re, found := s.refunds[id]
	s.mu.Unlock()
	if !ok || !found {
		writeJSON(w, http.StatusOK, reply(m.ID, nil, map[string]any{"code": -32002, "message": "Resource not found", "data": map[string]string{"uri": p.URI}}))
		return
	}
	b, _ := json.Marshal(re)
	result := map[string]any{"contents": []map[string]string{{"uri": p.URI, "mimeType": "application/json", "text": string(b)}}}
	if !s.f.Legacy {
		result["resultType"] = "complete"
	}
	writeJSON(w, http.StatusOK, reply(m.ID, result, nil))
}

// elicit answers a 2026-07-28 create_refund that has not answered the set
// elicitation with input_required, and records the answers of one that
// has; handled is true when it answered.
func (s *Server) elicit(w http.ResponseWriter, m message) (handled bool) {
	var p struct {
		Name           string         `json:"name"`
		InputResponses jsontext.Value `json:"inputResponses"`
		RequestState   string         `json:"requestState"`
	}
	_ = json.Unmarshal(m.Params, &p)
	s.mu.Lock()
	e := s.surface.elicit
	if e == nil || p.Name != "create_refund" {
		s.mu.Unlock()
		return false
	}
	if len(p.InputResponses) > 0 {
		s.surface.answered = append(s.surface.answered, p.InputResponses)
		s.surface.states = append(s.surface.states, p.RequestState)
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()
	key := e.Key
	if key == "" {
		key = "confirm"
	}
	params := map[string]any{"message": e.Message}
	if e.Mode != "" {
		params["mode"] = e.Mode
	}
	if len(e.Schema) > 0 {
		params["requestedSchema"] = e.Schema
	}
	if e.URL != "" {
		params["url"] = e.URL
	}
	result := map[string]any{"resultType": "input_required", "inputRequests": map[string]any{
		key: map[string]any{"method": "elicitation/create", "params": params},
	}}
	if e.RequestState != "" {
		result["requestState"] = e.RequestState
	}
	writeJSON(w, http.StatusOK, reply(m.ID, result, nil))
	return true
}
