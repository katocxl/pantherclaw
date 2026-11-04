// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package model

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
)

// created is the fixed creation time of every simulated answer.
const created = int64(1767225600)

// chatRequest is the part of a Chat Completions request the simulator reads.
type chatRequest struct {
	Model               string         `json:"model"`
	Messages            jsontext.Value `json:"messages"`
	MaxCompletionTokens *int64         `json:"max_completion_tokens"`
	MaxTokens           *int64         `json:"max_tokens"`
	N                   *int64         `json:"n"`
	Stream              bool           `json:"stream"`
	StreamOptions       *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

// chat answers POST /v1/chat/completions, as JSON or as chunks ending in
// data: [DONE]; a stream carries usage only when stream_options.include_usage
// is true, as the real API does (G0 M29 D826).
func (s *Server) chat(w http.ResponseWriter, r *http.Request, c call) {
	var req chatRequest
	if err := json.Unmarshal(c.body, &req); err != nil {
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: invalid JSON body")
		return
	}
	maxTokens := req.MaxCompletionTokens
	if maxTokens == nil {
		maxTokens = req.MaxTokens
	}
	n := int64(1)
	if req.N != nil {
		n = *req.N
	}
	switch {
	case req.Model == "":
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: you must provide a model parameter")
		return
	case len(req.Messages) == 0 || req.Messages.Kind() != '[':
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: messages is required")
		return
	case maxTokens != nil && *maxTokens < 1:
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: max tokens must be at least 1")
		return
	case n < 1 || n > 128:
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: n must be between 1 and 128")
		return
	}
	s.noteModel(req.Model)
	w.Header().Set("X-Request-Id", fmt.Sprintf("req_sim%017d", c.id))
	if req.Model == ModelError {
		apiError(w, apiOpenAI, http.StatusServiceUnavailable, "SIMULATED: the engine is currently overloaded")
		return
	}
	var maxT int64
	if maxTokens != nil {
		maxT = *maxTokens
	}
	in, out := inputTokens(c.body), outputTokens(req.Model, maxT)*n
	id := fmt.Sprintf("chatcmpl-sim%017d", c.id)
	tool := req.Model == ModelTool
	text, finish := Reply, "stop"
	if tool {
		text, finish = ToolReply, "tool_calls"
	}
	callID := fmt.Sprintf("call_sim%017d", c.id)
	usage := map[string]any{
		"prompt_tokens": in, "completion_tokens": out, "total_tokens": in + out,
		"prompt_tokens_details":     map[string]any{"cached_tokens": int64(0)},
		"completion_tokens_details": map[string]any{"reasoning_tokens": int64(0)},
	}
	if !req.Stream {
		choices := make([]any, 0, n)
		for i := range n {
			msg := map[string]any{"role": "assistant", "content": text, "refusal": nil}
			if tool {
				msg["tool_calls"] = []any{map[string]any{"id": callID, "type": "function", "function": map[string]any{"name": ToolName, "arguments": "{}"}}}
			}
			choices = append(choices, map[string]any{"index": i, "message": msg, "logprobs": nil, "finish_reason": finish})
		}
		body := map[string]any{
			"id": id, "object": "chat.completion", "created": created, "model": req.Model, "choices": choices,
			"usage": usage, "system_fingerprint": "fp_sim",
		}
		if req.Model == ModelCut {
			writeCut(w, body)
			return
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	includeUsage := req.StreamOptions != nil && req.StreamOptions.IncludeUsage
	chunk := func(choices []any) map[string]any {
		m := map[string]any{"id": id, "object": "chat.completion.chunk", "created": created, "model": req.Model, "system_fingerprint": "fp_sim", "choices": choices}
		if includeUsage {
			m["usage"] = nil
		}
		return m
	}
	choice := func(i int64, delta map[string]any, finish any) []any {
		return []any{map[string]any{"index": i, "delta": delta, "logprobs": nil, "finish_reason": finish}}
	}
	var events []event
	for i := range n {
		events = append(events, event{data: chunk(choice(i, map[string]any{"role": "assistant", "content": "", "refusal": nil}, nil))})
		for _, part := range []string{text[:len("SIMULATED")], text[len("SIMULATED"):]} {
			events = append(events, event{delta: true, data: chunk(choice(i, map[string]any{"content": part}, nil))})
		}
		if tool {
			events = append(events,
				event{delta: true, data: chunk(choice(i, map[string]any{"tool_calls": []any{map[string]any{
					"index": 0, "id": callID, "type": "function", "function": map[string]any{"name": ToolName, "arguments": ""},
				}}}, nil))},
				event{delta: true, data: chunk(choice(i, map[string]any{"tool_calls": []any{map[string]any{
					"index": 0, "function": map[string]any{"arguments": "{}"},
				}}}, nil))},
			)
		}
		events = append(events, event{data: chunk(choice(i, map[string]any{}, finish))})
	}
	if includeUsage && req.Model != ModelNoUsage {
		last := chunk([]any{})
		last["usage"] = usage
		events = append(events, event{data: last})
	}
	events = append(events, event{data: "[DONE]"})
	s.stream(w, r, events, req.Model == ModelCut)
}

// responsesRequest is the part of a Responses request the simulator reads.
type responsesRequest struct {
	Model           string         `json:"model"`
	Input           jsontext.Value `json:"input"`
	MaxOutputTokens *int64         `json:"max_output_tokens"`
	Stream          bool           `json:"stream"`
}

// responses answers POST /v1/responses, as JSON or as the Responses event
// stream: response.created, response.in_progress, output items with their
// deltas, response.completed (G0 M29 D826).
func (s *Server) responses(w http.ResponseWriter, r *http.Request, c call) {
	var req responsesRequest
	if err := json.Unmarshal(c.body, &req); err != nil {
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: invalid JSON body")
		return
	}
	switch {
	case req.Model == "":
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: you must provide a model parameter")
		return
	case len(req.Input) == 0 || (req.Input.Kind() != '"' && req.Input.Kind() != '['):
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: input is required")
		return
	case req.MaxOutputTokens != nil && *req.MaxOutputTokens < 1:
		apiError(w, apiOpenAI, http.StatusBadRequest, "SIMULATED: max_output_tokens must be at least 1")
		return
	}
	s.noteModel(req.Model)
	w.Header().Set("X-Request-Id", fmt.Sprintf("req_sim%017d", c.id))
	if req.Model == ModelError {
		apiError(w, apiOpenAI, http.StatusServiceUnavailable, "SIMULATED: the engine is currently overloaded")
		return
	}
	var maxT int64
	var maxField any
	if req.MaxOutputTokens != nil {
		maxT, maxField = *req.MaxOutputTokens, *req.MaxOutputTokens
	}
	in, out := inputTokens(c.body), outputTokens(req.Model, maxT)
	id := fmt.Sprintf("resp_sim%017d", c.id)
	msgID := fmt.Sprintf("msg_sim%017d", c.id)
	fcID := fmt.Sprintf("fc_sim%017d", c.id)
	callID := fmt.Sprintf("call_sim%017d", c.id)
	tool := req.Model == ModelTool
	text := Reply
	if tool {
		text = ToolReply
	}
	part := func(t string) map[string]any {
		return map[string]any{"type": "output_text", "text": t, "annotations": []any{}}
	}
	message := func(status string, content []any) map[string]any {
		return map[string]any{"type": "message", "id": msgID, "status": status, "role": "assistant", "content": content}
	}
	fcall := func(status, args string) map[string]any {
		return map[string]any{"type": "function_call", "id": fcID, "call_id": callID, "name": ToolName, "arguments": args, "status": status}
	}
	output := []any{message("completed", []any{part(text)})}
	if tool {
		output = append(output, fcall("completed", "{}"))
	}
	resp := func(status string, output []any, usage any) map[string]any {
		return map[string]any{
			"id": id, "object": "response", "created_at": created, "status": status, "model": req.Model, "output": output,
			"usage": usage, "max_output_tokens": maxField, "error": nil, "incomplete_details": nil,
		}
	}
	usage := map[string]any{
		"input_tokens": in, "input_tokens_details": map[string]any{"cached_tokens": int64(0)},
		"output_tokens": out, "output_tokens_details": map[string]any{"reasoning_tokens": int64(0)},
		"total_tokens": in + out,
	}
	if !req.Stream {
		if req.Model == ModelCut {
			writeCut(w, resp("completed", output, usage))
			return
		}
		writeJSON(w, http.StatusOK, resp("completed", output, usage))
		return
	}
	seq := 0
	ev := func(name string, delta bool, fields map[string]any) event {
		fields["type"] = name
		fields["sequence_number"] = seq
		seq++
		return event{name: name, data: fields, delta: delta}
	}
	events := []event{
		ev("response.created", false, map[string]any{"response": resp("in_progress", []any{}, nil)}),
		ev("response.in_progress", false, map[string]any{"response": resp("in_progress", []any{}, nil)}),
		ev("response.output_item.added", false, map[string]any{"output_index": 0, "item": message("in_progress", []any{})}),
		ev("response.content_part.added", false, map[string]any{"item_id": msgID, "output_index": 0, "content_index": 0, "part": part("")}),
	}
	for _, d := range []string{text[:len("SIMULATED")], text[len("SIMULATED"):]} {
		events = append(events, ev("response.output_text.delta", true, map[string]any{"item_id": msgID, "output_index": 0, "content_index": 0, "delta": d}))
	}
	events = append(events,
		ev("response.output_text.done", false, map[string]any{"item_id": msgID, "output_index": 0, "content_index": 0, "text": text}),
		ev("response.content_part.done", false, map[string]any{"item_id": msgID, "output_index": 0, "content_index": 0, "part": part(text)}),
		ev("response.output_item.done", false, map[string]any{"output_index": 0, "item": message("completed", []any{part(text)})}),
	)
	if tool {
		events = append(events,
			ev("response.output_item.added", false, map[string]any{"output_index": 1, "item": fcall("in_progress", "")}),
			ev("response.function_call_arguments.delta", true, map[string]any{"item_id": fcID, "output_index": 1, "delta": "{}"}),
			ev("response.function_call_arguments.done", false, map[string]any{"item_id": fcID, "output_index": 1, "arguments": "{}"}),
			ev("response.output_item.done", false, map[string]any{"output_index": 1, "item": fcall("completed", "{}")}),
		)
	}
	events = append(events, ev("response.completed", false, map[string]any{"response": resp("completed", output, usage)}))
	s.stream(w, r, events, req.Model == ModelCut)
}
