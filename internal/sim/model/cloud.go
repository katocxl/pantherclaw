// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package model

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Cloud routes (G0 M31 D961): Anthropic models on Vertex AI under /vertex
// and Bedrock Converse under /bedrock, each with the provider's own
// credential.
//
//   - POST /vertex/token is a Google token endpoint: a jwt-bearer grant with a
//     signed-looking assertion gets the simulator's key as its access token,
//     which the Vertex routes then take as a Bearer token.
//   - POST /vertex/models/{id}:rawPredict and :streamRawPredict take a
//     Messages body with anthropic_version vertex-2023-10-16 and the model in
//     the path; streamRawPredict always streams.
//   - POST /bedrock/model/{id}/converse and /converse-stream take a Converse
//     body signed with SigV4 for the service bedrock with session
//     credentials. The simulator checks the signature's form, not its value:
//     the aws simulator is the check of the signing itself. converse-stream
//     answers an AWS event stream whose metadata event carries the usage.
const (
	OpVertex         = "vertex"
	OpVertexToken    = "vertex_token" //nolint:gosec // G101: an operation name, not a credential
	OpBedrock        = "converse"
	OpBedrockStream  = "converse_stream"
	VertexVersion    = "vertex-2023-10-16"
	eventStreamType  = "application/vnd.amazon.eventstream"
	vertexTokenGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101: a grant type, not a credential
)

func (s *Server) cloudRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /vertex/token", s.vertexToken)
	mux.HandleFunc("POST /vertex/models/{call}", s.authed(OpVertex, fixed(apiAnthropic), s.vertex))
	mux.HandleFunc("POST /bedrock/model/{id}/converse", s.authed(OpBedrock, fixed(apiBedrock), s.converse(false)))
	mux.HandleFunc("POST /bedrock/model/{id}/converse-stream", s.authed(OpBedrockStream, fixed(apiBedrock), s.converse(true)))
}

var assertionRe = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// vertexToken answers a jwt-bearer grant with the simulator's key.
func (s *Server) vertexToken(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	form, perr := url.ParseQuery(string(body))
	s.mu.Lock()
	s.stats.Requests++
	ok := err == nil && perr == nil && form.Get("grant_type") == vertexTokenGrant && assertionRe.MatchString(form.Get("assertion"))
	if ok {
		s.stats.Calls[OpVertexToken]++
	} else {
		s.stats.Unauthorized++
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "SIMULATED: invalid assertion"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": s.key, "token_type": "Bearer", "expires_in": 3599})
}

// vertex answers rawPredict and streamRawPredict.
func (s *Server) vertex(w http.ResponseWriter, r *http.Request, c call) {
	id, method, ok := strings.Cut(r.PathValue("call"), ":")
	if !ok || id == "" || (method != "rawPredict" && method != "streamRawPredict") {
		apiError(w, apiAnthropic, http.StatusNotFound, "SIMULATED: no such route")
		return
	}
	var req struct {
		anthropicRequest
		Version string `json:"anthropic_version"`
	}
	if err := json.Unmarshal(c.body, &req); err != nil {
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: invalid JSON body")
		return
	}
	switch {
	case req.Version != VertexVersion:
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: anthropic_version: must be "+VertexVersion)
		return
	case req.Model != "" && req.Model != id:
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: model: must match the path")
		return
	case len(req.Messages) == 0 || req.Messages.Kind() != '[':
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: messages: Field required")
		return
	case req.MaxTokens == nil || *req.MaxTokens < 1:
		apiError(w, apiAnthropic, http.StatusBadRequest, "SIMULATED: max_tokens: Field required")
		return
	}
	req.Model = id
	req.Stream = req.Stream || method == "streamRawPredict"
	s.noteModel(id)
	s.answerMessages(w, r, c, req.anthropicRequest)
}

// sigV4Re is a SigV4 Authorization header for the service bedrock.
var sigV4Re = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([A-Z0-9]{16,128})/[0-9]{8}/[a-z0-9-]+/bedrock/aws4_request, SignedHeaders=[a-z0-9;-]+, Signature=[0-9a-f]{64}$`)

// sigV4Key is the access key id of a well-formed SigV4 request with a
// session token and a date; nil otherwise.
func sigV4Key(r *http.Request) []string {
	m := sigV4Re.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil || r.Header.Get("X-Amz-Date") == "" || r.Header.Get("X-Amz-Security-Token") == "" {
		return nil
	}
	return []string{m[1]}
}

// converseRequest is the part of a Converse request the simulator reads.
type converseRequest struct {
	Messages        jsontext.Value `json:"messages"`
	InferenceConfig *struct {
		MaxTokens *int64 `json:"maxTokens"`
	} `json:"inferenceConfig"`
}

// converse answers Converse or ConverseStream.
func (s *Server) converse(streamed bool) func(http.ResponseWriter, *http.Request, call) {
	return func(w http.ResponseWriter, r *http.Request, c call) {
		id := r.PathValue("id")
		var req converseRequest
		if err := json.Unmarshal(c.body, &req); err != nil {
			bedrockError(w, http.StatusBadRequest, "SIMULATED: invalid JSON body")
			return
		}
		if len(req.Messages) == 0 || req.Messages.Kind() != '[' {
			bedrockError(w, http.StatusBadRequest, "SIMULATED: messages is required")
			return
		}
		var maxTokens int64
		if req.InferenceConfig != nil && req.InferenceConfig.MaxTokens != nil {
			if maxTokens = *req.InferenceConfig.MaxTokens; maxTokens < 1 {
				bedrockError(w, http.StatusBadRequest, "SIMULATED: maxTokens must be at least 1")
				return
			}
		}
		s.noteModel(id)
		w.Header().Set("X-Amzn-Requestid", fmt.Sprintf("sim-%017d", c.id))
		if id == ModelError {
			w.Header().Set("Retry-After", "1")
			bedrockError(w, http.StatusServiceUnavailable, "SIMULATED: service unavailable")
			return
		}
		in, out := inputTokens(c.body), outputTokens(id, maxTokens)
		tool := id == ModelTool
		text, stop := Reply, "end_turn"
		if tool {
			text, stop = ToolReply, "tool_use"
		}
		toolID := fmt.Sprintf("tooluse_sim%017d", c.id)
		usage := map[string]any{"inputTokens": in, "outputTokens": out, "totalTokens": in + out}
		if !streamed {
			content := []any{map[string]any{"text": text}}
			if tool {
				content = append(content, map[string]any{"toolUse": map[string]any{"toolUseId": toolID, "name": ToolName, "input": map[string]any{}}})
			}
			msg := map[string]any{
				"output":     map[string]any{"message": map[string]any{"role": "assistant", "content": content}},
				"stopReason": stop, "usage": usage, "metrics": map[string]any{"latencyMs": 1},
			}
			if id == ModelCut {
				writeCut(w, msg)
				return
			}
			writeJSON(w, http.StatusOK, msg)
			return
		}
		events := []event{{name: "messageStart", data: map[string]any{"role": "assistant"}}}
		first, rest := text[:len("SIMULATED")], text[len("SIMULATED"):]
		for _, part := range []string{first, rest} {
			events = append(events, event{name: "contentBlockDelta", delta: true, data: map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": part}}})
		}
		events = append(events, event{name: "contentBlockStop", data: map[string]any{"contentBlockIndex": 0}})
		if tool {
			events = append(events,
				event{name: "contentBlockStart", data: map[string]any{"contentBlockIndex": 1, "start": map[string]any{"toolUse": map[string]any{"toolUseId": toolID, "name": ToolName}}}},
				event{name: "contentBlockDelta", delta: true, data: map[string]any{"contentBlockIndex": 1, "delta": map[string]any{"toolUse": map[string]any{"input": "{}"}}}},
				event{name: "contentBlockStop", data: map[string]any{"contentBlockIndex": 1}},
			)
		}
		events = append(events, event{name: "messageStop", data: map[string]any{"stopReason": stop}})
		if id != ModelNoUsage {
			events = append(events, event{name: "metadata", data: map[string]any{"usage": usage, "metrics": map[string]any{"latencyMs": 1}}})
		}
		s.eventStream(w, r, events, id == ModelCut)
	}
}

// eventStream writes events as AWS event stream frames, flushing each, and
// drops the connection after the first delta when cut is set.
func (s *Server) eventStream(w http.ResponseWriter, r *http.Request, events []event, cut bool) {
	w.Header().Set("Content-Type", eventStreamType)
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
		payload, err := json.Marshal(ev.data, json.Deterministic(true))
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if _, err := w.Write(frame(map[string]string{":event-type": ev.name, ":content-type": "application/json", ":message-type": "event"}, payload)); err != nil {
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

// frame encodes one event stream frame with string headers, in a fixed
// order.
func frame(headers map[string]string, payload []byte) []byte {
	var h bytes.Buffer
	for _, name := range []string{":event-type", ":content-type", ":message-type", ":exception-type"} {
		v, ok := headers[name]
		if !ok {
			continue
		}
		h.WriteByte(byte(len(name))) //nolint:gosec // G115: one of the four fixed header names above
		h.WriteString(name)
		h.WriteByte(7)
		_ = binary.Write(&h, binary.BigEndian, uint16(len(v))) //nolint:gosec // G115: the simulator's own short header values
		h.WriteString(v)
	}
	total := 12 + h.Len() + len(payload) + 4
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(total))   //nolint:gosec // G115: a simulated frame, far below 4 GiB
	out = binary.BigEndian.AppendUint32(out, uint32(h.Len())) //nolint:gosec // G115: four short headers
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	out = append(out, h.Bytes()...)
	out = append(out, payload...)
	return binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
}

// bedrockError answers status in Bedrock's error shape.
func bedrockError(w http.ResponseWriter, status int, msg string) {
	t := "InternalServerException"
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		t = "ValidationException"
	case http.StatusUnauthorized:
		status, t = http.StatusForbidden, "UnrecognizedClientException"
	case http.StatusForbidden:
		t = "AccessDeniedException"
	case http.StatusNotFound:
		t = "ResourceNotFoundException"
	case http.StatusTooManyRequests:
		t = "ThrottlingException"
	case http.StatusServiceUnavailable:
		t = "ServiceUnavailableException"
	}
	w.Header().Set("X-Amzn-Errortype", t)
	writeJSON(w, status, map[string]any{"message": msg})
}
