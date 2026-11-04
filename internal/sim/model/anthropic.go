// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package model

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
)

// anthropicRequest is the part of a Messages request the simulator reads.
type anthropicRequest struct {
	Model     string         `json:"model"`
	MaxTokens *int64         `json:"max_tokens"`
	Messages  jsontext.Value `json:"messages"`
	Stream    bool           `json:"stream"`
}

func (s *Server) parseAnthropic(w http.ResponseWriter, c call, needMax bool) (anthropicRequest, bool) {
	var req anthropicRequest
	if err := json.Unmarshal(c.body, &req); err != nil {
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: invalid JSON body")
		return req, false
	}
	switch {
	case req.Model == "":
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: model: Field required")
	case len(req.Messages) == 0 || req.Messages.Kind() != '[':
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: messages: Field required")
	case needMax && req.MaxTokens == nil:
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: max_tokens: Field required")
	case req.MaxTokens != nil && *req.MaxTokens < 1:
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: max_tokens: must be at least 1")
	default:
		s.noteModel(req.Model)
		return req, true
	}
	return req, false
}

// countTokens answers POST /v1/messages/count_tokens.
func (s *Server) countTokens(w http.ResponseWriter, _ *http.Request, c call) {
	if _, ok := s.parseAnthropic(w, c, false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"input_tokens": inputTokens(c.body)})
}

// messages answers POST /v1/messages, as JSON or as the Messages event
// stream: message_start, content_block_start, ping, content_block_delta…,
// content_block_stop, message_delta, message_stop.
func (s *Server) messages(w http.ResponseWriter, r *http.Request, c call) {
	req, ok := s.parseAnthropic(w, c, true)
	if !ok {
		return
	}
	s.answerMessages(w, r, c, req)
}

// answerMessages answers a checked Messages request (the Messages API's
// own route, or Vertex AI's rawPredict and streamRawPredict, G0 M31 D961).
func (s *Server) answerMessages(w http.ResponseWriter, r *http.Request, c call, req anthropicRequest) {
	w.Header().Set("Request-Id", fmt.Sprintf("req_sim%017d", c.id))
	if req.Model == ModelError {
		apiError(w, apiAnthropic, 529, "SIMULATED: Overloaded")
		return
	}
	in, out := inputTokens(c.body), outputTokens(req.Model, *req.MaxTokens)
	id := fmt.Sprintf("msg_sim%017d", c.id)
	toolID := fmt.Sprintf("toolu_sim%017d", c.id)
	tool := req.Model == ModelTool
	text, stop := Reply, "end_turn"
	if tool {
		text, stop = ToolReply, "tool_use"
	}
	usage := func(output int64) map[string]any {
		return map[string]any{"input_tokens": in, "output_tokens": output, "cache_creation_input_tokens": int64(0), "cache_read_input_tokens": int64(0)}
	}
	if !req.Stream {
		content := []any{map[string]any{"type": "text", "text": text}}
		if tool {
			content = append(content, map[string]any{"type": "tool_use", "id": toolID, "name": ToolName, "input": map[string]any{}})
		}
		msg := map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": req.Model, "content": content,
			"stop_reason": stop, "stop_sequence": nil, "usage": usage(out),
		}
		if req.Model == ModelCut {
			writeCut(w, msg)
			return
		}
		writeJSON(w, http.StatusOK, msg)
		return
	}
	events := []event{
		{name: "message_start", data: map[string]any{"type": "message_start", "message": map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": req.Model, "content": []any{},
			"stop_reason": nil, "stop_sequence": nil, "usage": usage(1),
		}}},
		{name: "content_block_start", data: map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]any{"type": "text", "text": ""}}},
		{name: "ping", data: map[string]any{"type": "ping"}},
	}
	first, rest := text[:len("SIMULATED")], text[len("SIMULATED"):]
	for _, part := range []string{first, rest} {
		events = append(events, event{name: "content_block_delta", delta: true, data: map[string]any{
			"type": "content_block_delta", "index": 0, "delta": map[string]any{"type": "text_delta", "text": part},
		}})
	}
	events = append(events, event{name: "content_block_stop", data: map[string]any{"type": "content_block_stop", "index": 0}})
	if tool {
		events = append(events,
			event{name: "content_block_start", data: map[string]any{"type": "content_block_start", "index": 1, "content_block": map[string]any{
				"type": "tool_use", "id": toolID, "name": ToolName, "input": map[string]any{},
			}}},
			event{name: "content_block_delta", delta: true, data: map[string]any{
				"type": "content_block_delta", "index": 1, "delta": map[string]any{"type": "input_json_delta", "partial_json": "{}"},
			}},
			event{name: "content_block_stop", data: map[string]any{"type": "content_block_stop", "index": 1}},
		)
	}
	events = append(events,
		event{name: "message_delta", data: map[string]any{"type": "message_delta", "delta": map[string]any{"stop_reason": stop, "stop_sequence": nil}, "usage": usage(out)}},
		event{name: "message_stop", data: map[string]any{"type": "message_stop"}},
	)
	s.stream(w, r, events, req.Model == ModelCut)
}
