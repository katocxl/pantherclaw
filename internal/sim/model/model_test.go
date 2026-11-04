// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package model

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

const anthropicVersion = "2023-06-01"

type fixture struct {
	t   *testing.T
	sim *Server
	url string
	cl  *http.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sim := New("", Faults{}, slog.New(slog.DiscardHandler))
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	return &fixture{t: t, sim: sim, url: ts.URL, cl: ts.Client()}
}

// reply is a read answer: its body as read and the error that ended the
// read (a cut answer ends in one).
type reply struct {
	StatusCode    int
	Header        http.Header
	ContentLength int64
	Body          io.Reader
	raw           []byte
	readErr       error
}

// do sends a request and reads the whole answer; hdr holds header pairs.
func (f *fixture) do(method, path, body string, hdr ...string) *reply {
	f.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(f.t.Context(), method, f.url+path, rd)
	if err != nil {
		f.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, readErr := io.ReadAll(res.Body)
	return &reply{
		StatusCode: res.StatusCode, Header: res.Header, ContentLength: res.ContentLength,
		Body: bytes.NewReader(raw), raw: raw, readErr: readErr,
	}
}

func anthropicHdr() []string {
	return []string{"X-Api-Key", DefaultKey, "Anthropic-Version", anthropicVersion}
}
func openaiHdr() []string { return []string{"Authorization", "Bearer " + DefaultKey} }

func decode(t *testing.T, res *reply) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.UnmarshalRead(res.Body, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// path walks a decoded JSON value by keys and indexes.
func path(v any, keys ...any) any {
	for _, k := range keys {
		switch k := k.(type) {
		case string:
			m, _ := v.(map[string]any)
			v = m[k]
		case int:
			a, _ := v.([]any)
			if k >= len(a) {
				return nil
			}
			v = a[k]
		}
	}
	return v
}

type sse struct {
	name string
	data string
}

// readSSE reads every event of a stream and the error that ended it.
func readSSE(t *testing.T, r io.Reader) ([]sse, error) {
	t.Helper()
	var out []sse
	var cur sse
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			out = append(out, cur)
			cur = sse{}
		case strings.HasPrefix(line, "event: "):
			cur.name = line[len("event: "):]
		case strings.HasPrefix(line, "data: "):
			cur.data = line[len("data: "):]
		default:
			t.Fatalf("not an SSE line: %q", line)
		}
	}
	return out, sc.Err()
}

func (e sse) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(e.data), &m); err != nil {
		t.Fatalf("event %q: %v", e.name, err)
	}
	return m
}

func num(v any) int64 { f, _ := v.(float64); return int64(f) }

// Covers: F985
func TestAuthAcceptsOnlyTheKeyInAnyOfItsHeaders(t *testing.T) {
	f := newFixture(t)
	body := `{"model":"sim-model","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`
	for name, hdr := range map[string][]string{
		"x-api-key": {"X-Api-Key", DefaultKey},
		"bearer":    {"Authorization", "Bearer " + DefaultKey},
		"api-key":   {"Api-Key", DefaultKey},
	} {
		if res := f.do("POST", "/v1/messages", body, hdr...); res.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", name, res.StatusCode)
		}
	}
	for name, hdr := range map[string][]string{
		"none":      nil,
		"wrong key": {"X-Api-Key", "sk-wrong"},
		"basic":     {"Authorization", "Basic " + DefaultKey},
	} {
		res := f.do("POST", "/v1/messages", body, hdr...)
		m := decode(t, res)
		if res.StatusCode != http.StatusUnauthorized || path(m, "type") != "error" || path(m, "error", "type") != "authentication_error" {
			t.Errorf("%s: %d %v", name, res.StatusCode, m)
		}
		res = f.do("POST", "/v1/chat/completions", `{"model":"sim-model","messages":[]}`, hdr...)
		m = decode(t, res)
		if res.StatusCode != http.StatusUnauthorized || path(m, "error", "code") != "invalid_api_key" {
			t.Errorf("%s (openai): %d %v", name, res.StatusCode, m)
		}
	}
	st := f.sim.Stats()
	if st.Unauthorized != 6 || st.Calls[OpMessages] != 3 || st.LastKey != DefaultKey {
		t.Fatalf("stats %+v", st)
	}
	if !f.sim.Presented("sk-wrong") || f.sim.Presented("sk-never-sent") {
		t.Fatal("Presented does not track what was sent")
	}
}

// Covers: F985
func TestAnthropicMessages(t *testing.T) {
	msg := func(model, extra string) string {
		return `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]` + extra + `}`
	}
	for name, tc := range map[string]struct {
		body   string
		status int
		check  func(t *testing.T, body string, m map[string]any)
	}{
		"default": {msg("claude-x", `,"max_tokens":100`), 200, func(t *testing.T, body string, m map[string]any) {
			if path(m, "type") != "message" || path(m, "role") != "assistant" || path(m, "model") != "claude-x" ||
				path(m, "content", 0, "type") != "text" || path(m, "content", 0, "text") != Reply || path(m, "stop_reason") != "end_turn" {
				t.Fatalf("%v", m)
			}
			if num(path(m, "usage", "input_tokens")) != (int64(len(body))+3)/4 || num(path(m, "usage", "output_tokens")) != 8 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"small max": {msg("claude-x", `,"max_tokens":3`), 200, func(t *testing.T, _ string, m map[string]any) {
			if num(path(m, "usage", "output_tokens")) != 3 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"sim-max": {msg(ModelMax, `,"max_tokens":5000`), 200, func(t *testing.T, _ string, m map[string]any) {
			if num(path(m, "usage", "output_tokens")) != 5000 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"sim-tool": {msg(ModelTool, `,"max_tokens":100`), 200, func(t *testing.T, _ string, m map[string]any) {
			if path(m, "content", 0, "text") != ToolReply || path(m, "content", 1, "type") != "tool_use" ||
				path(m, "content", 1, "name") != ToolName || path(m, "stop_reason") != "tool_use" {
				t.Fatalf("%v", m)
			}
		}},
		"sim-error": {msg(ModelError, `,"max_tokens":100`), 529, func(t *testing.T, _ string, m map[string]any) {
			if path(m, "type") != "error" || path(m, "error", "type") != "overloaded_error" {
				t.Fatalf("%v", m)
			}
		}},
		"no max_tokens":  {msg("claude-x", ""), 400, nil},
		"zero max":       {msg("claude-x", `,"max_tokens":0`), 400, nil},
		"no model":       {`{"max_tokens":1,"messages":[]}`, 400, nil},
		"no messages":    {`{"model":"m","max_tokens":1}`, 400, nil},
		"not json":       {`{"model":`, 400, nil},
		"duplicate name": {`{"model":"m","max_tokens":1,"max_tokens":2,"messages":[]}`, 400, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			res := f.do("POST", "/v1/messages", tc.body, anthropicHdr()...)
			m := decode(t, res)
			if res.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %v", res.StatusCode, tc.status, m)
			}
			if tc.status == 400 && path(m, "error", "type") != "invalid_request_error" {
				t.Fatalf("%v", m)
			}
			if tc.check != nil {
				tc.check(t, tc.body, m)
			}
		})
	}
}

// Covers: F985
func TestAnthropicCountTokensAndModels(t *testing.T) {
	f := newFixture(t)
	body := `{"model":"m","messages":[{"role":"user","content":"count me"}]}`
	m := decode(t, f.do("POST", "/v1/messages/count_tokens", body, anthropicHdr()...))
	if num(m["input_tokens"]) != (int64(len(body))+3)/4 || len(m) != 1 {
		t.Fatalf("%v", m)
	}
	m = decode(t, f.do("GET", "/v1/models", "", anthropicHdr()...))
	if path(m, "data", 0, "type") != "model" || path(m, "data", 0, "id") != ModelDefault || path(m, "has_more") != false || path(m, "last_id") != ModelTool {
		t.Fatalf("%v", m)
	}
	m = decode(t, f.do("GET", "/v1/models/claude-x", "", anthropicHdr()...))
	if path(m, "id") != "claude-x" || !strings.HasPrefix(path(m, "display_name").(string), "SIMULATED") {
		t.Fatalf("%v", m)
	}
	// Without anthropic-version the models list is OpenAI's.
	m = decode(t, f.do("GET", "/v1/models", "", openaiHdr()...))
	if path(m, "object") != "list" || path(m, "data", 0, "object") != "model" {
		t.Fatalf("%v", m)
	}
	m = decode(t, f.do("GET", "/v1/models/gpt-x", "", openaiHdr()...))
	if path(m, "id") != "gpt-x" || path(m, "owned_by") != "pantherclaw-sim" {
		t.Fatalf("%v", m)
	}
	if st := f.sim.Stats(); st.Calls[OpCountTokens] != 1 || st.Calls[OpModels] != 4 {
		t.Fatalf("%+v", st)
	}
}

// Covers: F985
func TestOpenAIChat(t *testing.T) {
	msg := func(model, extra string) string {
		return `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]` + extra + `}`
	}
	for name, tc := range map[string]struct {
		body   string
		status int
		check  func(t *testing.T, body string, m map[string]any)
	}{
		"default": {msg("gpt-x", ""), 200, func(t *testing.T, body string, m map[string]any) {
			if path(m, "object") != "chat.completion" || path(m, "choices", 0, "message", "content") != Reply ||
				path(m, "choices", 0, "finish_reason") != "stop" {
				t.Fatalf("%v", m)
			}
			in := (int64(len(body)) + 3) / 4
			if num(path(m, "usage", "prompt_tokens")) != in || num(path(m, "usage", "completion_tokens")) != 8 ||
				num(path(m, "usage", "total_tokens")) != in+8 || num(path(m, "usage", "prompt_tokens_details", "cached_tokens")) != 0 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"max_completion_tokens wins": {msg("gpt-x", `,"max_completion_tokens":2,"max_tokens":6`), 200, func(t *testing.T, _ string, m map[string]any) {
			if num(path(m, "usage", "completion_tokens")) != 2 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"legacy max_tokens": {msg("gpt-x", `,"max_tokens":6`), 200, func(t *testing.T, _ string, m map[string]any) {
			if num(path(m, "usage", "completion_tokens")) != 6 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"n choices": {msg("gpt-x", `,"n":3,"max_completion_tokens":4`), 200, func(t *testing.T, _ string, m map[string]any) {
			if len(path(m, "choices").([]any)) != 3 || num(path(m, "choices", 2, "index")) != 2 || num(path(m, "usage", "completion_tokens")) != 12 {
				t.Fatalf("%v", m)
			}
		}},
		"sim-max": {msg(ModelMax, `,"max_completion_tokens":900`), 200, func(t *testing.T, _ string, m map[string]any) {
			if num(path(m, "usage", "completion_tokens")) != 900 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"sim-tool": {msg(ModelTool, ""), 200, func(t *testing.T, _ string, m map[string]any) {
			if path(m, "choices", 0, "finish_reason") != "tool_calls" || path(m, "choices", 0, "message", "tool_calls", 0, "function", "name") != ToolName ||
				path(m, "choices", 0, "message", "content") != ToolReply {
				t.Fatalf("%v", m)
			}
		}},
		"sim-error": {msg(ModelError, ""), 503, func(t *testing.T, _ string, m map[string]any) {
			if path(m, "error", "type") != "server_error" || !strings.HasPrefix(path(m, "error", "message").(string), "SIMULATED") {
				t.Fatalf("%v", m)
			}
		}},
		"no model":    {`{"messages":[]}`, 400, nil},
		"no messages": {`{"model":"m"}`, 400, nil},
		"bad n":       {msg("m", `,"n":0`), 400, nil},
		"zero max":    {msg("m", `,"max_completion_tokens":0`), 400, nil},
		"float max":   {msg("m", `,"max_completion_tokens":1.5`), 400, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			res := f.do("POST", "/v1/chat/completions", tc.body, openaiHdr()...)
			m := decode(t, res)
			if res.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %v", res.StatusCode, tc.status, m)
			}
			if tc.status == 400 && path(m, "error", "type") != "invalid_request_error" {
				t.Fatalf("%v", m)
			}
			if tc.check != nil {
				tc.check(t, tc.body, m)
			}
		})
	}
}

// Covers: F985
func TestOpenAIResponses(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		status int
		check  func(t *testing.T, body string, m map[string]any)
	}{
		"default": {`{"model":"gpt-x","input":"hi","max_output_tokens":50}`, 200, func(t *testing.T, body string, m map[string]any) {
			if path(m, "object") != "response" || path(m, "status") != "completed" || path(m, "output", 0, "type") != "message" ||
				path(m, "output", 0, "content", 0, "type") != "output_text" || path(m, "output", 0, "content", 0, "text") != Reply ||
				num(path(m, "max_output_tokens")) != 50 {
				t.Fatalf("%v", m)
			}
			in := (int64(len(body)) + 3) / 4
			if num(path(m, "usage", "input_tokens")) != in || num(path(m, "usage", "output_tokens")) != 8 ||
				num(path(m, "usage", "total_tokens")) != in+8 || num(path(m, "usage", "input_tokens_details", "cached_tokens")) != 0 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"array input": {`{"model":"gpt-x","input":[{"role":"user","content":"hi"}]}`, 200, nil},
		"sim-max": {`{"model":"sim-max","input":"hi","max_output_tokens":77}`, 200, func(t *testing.T, _ string, m map[string]any) {
			if num(path(m, "usage", "output_tokens")) != 77 {
				t.Fatalf("usage %v", path(m, "usage"))
			}
		}},
		"sim-tool": {`{"model":"sim-tool","input":"hi"}`, 200, func(t *testing.T, _ string, m map[string]any) {
			if path(m, "output", 1, "type") != "function_call" || path(m, "output", 1, "name") != ToolName || path(m, "output", 1, "arguments") != "{}" {
				t.Fatalf("%v", m)
			}
		}},
		"sim-error": {`{"model":"sim-error","input":"hi"}`, 503, nil},
		"no input":  {`{"model":"gpt-x"}`, 400, nil},
		"bad input": {`{"model":"gpt-x","input":3}`, 400, nil},
		"zero max":  {`{"model":"gpt-x","input":"hi","max_output_tokens":0}`, 400, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			res := f.do("POST", "/v1/responses", tc.body, openaiHdr()...)
			m := decode(t, res)
			if res.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %v", res.StatusCode, tc.status, m)
			}
			if tc.check != nil {
				tc.check(t, tc.body, m)
			}
		})
	}
}

// types lists each event's name, or for unnamed events (OpenAI chat) its
// object and finish reason.
func types(t *testing.T, evs []sse) []string {
	t.Helper()
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		switch {
		case e.name != "":
			if typ := e.json(t)["type"]; typ != e.name {
				t.Fatalf("event %q carries type %v", e.name, typ)
			}
			out = append(out, e.name)
		case e.data == "[DONE]":
			out = append(out, "[DONE]")
		default:
			m := e.json(t)
			switch {
			case len(path(m, "choices").([]any)) == 0:
				out = append(out, "usage")
			case path(m, "choices", 0, "finish_reason") != nil:
				out = append(out, "finish")
			case path(m, "choices", 0, "delta", "role") != nil:
				out = append(out, "role")
			case path(m, "choices", 0, "delta", "tool_calls") != nil:
				out = append(out, "tool")
			default:
				out = append(out, "content")
			}
		}
	}
	return out
}

// text joins every text delta of a stream.
func text(t *testing.T, evs []sse) string {
	var b strings.Builder
	for _, e := range evs {
		if e.data == "[DONE]" {
			continue
		}
		m := e.json(t)
		for _, v := range []any{path(m, "delta", "text"), path(m, "choices", 0, "delta", "content")} {
			if s, ok := v.(string); ok {
				b.WriteString(s)
			}
		}
		if e.name == "response.output_text.delta" {
			b.WriteString(m["delta"].(string))
		}
	}
	return b.String()
}

// Covers: F985
func TestStreamEventOrder(t *testing.T) {
	anthropic := []string{"message_start", "content_block_start", "ping", "content_block_delta", "content_block_delta", "content_block_stop"}
	responses := []string{
		"response.created", "response.in_progress", "response.output_item.added", "response.content_part.added",
		"response.output_text.delta", "response.output_text.delta", "response.output_text.done", "response.content_part.done", "response.output_item.done",
	}
	for name, tc := range map[string]struct {
		path, body string
		hdr        []string
		want       []string
		text       string
	}{
		"anthropic": {
			"/v1/messages", `{"model":"m","max_tokens":5,"stream":true,"messages":[]}`, anthropicHdr(),
			append(slices.Clone(anthropic), "message_delta", "message_stop"), Reply,
		},
		"anthropic tool": {
			"/v1/messages", `{"model":"sim-tool","max_tokens":5,"stream":true,"messages":[]}`, anthropicHdr(),
			append(slices.Clone(anthropic), "content_block_start", "content_block_delta", "content_block_stop", "message_delta", "message_stop"), ToolReply,
		},
		"chat without usage": {
			"/v1/chat/completions", `{"model":"m","stream":true,"messages":[]}`, openaiHdr(),
			[]string{"role", "content", "content", "finish", "[DONE]"},
			Reply,
		},
		"chat with usage": {
			"/v1/chat/completions", `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[]}`, openaiHdr(),
			[]string{"role", "content", "content", "finish", "usage", "[DONE]"},
			Reply,
		},
		"chat sim-no-usage": {
			"/v1/chat/completions", `{"model":"sim-no-usage","stream":true,"stream_options":{"include_usage":true},"messages":[]}`, openaiHdr(),
			[]string{"role", "content", "content", "finish", "[DONE]"},
			Reply,
		},
		"chat tool": {
			"/v1/chat/completions", `{"model":"sim-tool","stream":true,"messages":[]}`, openaiHdr(),
			[]string{"role", "content", "content", "tool", "tool", "finish", "[DONE]"},
			ToolReply,
		},
		"chat two choices": {
			"/v1/chat/completions", `{"model":"m","n":2,"stream":true,"messages":[]}`, openaiHdr(),
			[]string{"role", "content", "content", "finish", "role", "content", "content", "finish", "[DONE]"},
			Reply + Reply,
		},
		"responses": {
			"/v1/responses", `{"model":"m","stream":true,"input":"hi"}`, openaiHdr(),
			append(slices.Clone(responses), "response.completed"), Reply,
		},
		"responses tool": {
			"/v1/responses", `{"model":"sim-tool","stream":true,"input":"hi"}`, openaiHdr(),
			append(slices.Clone(responses), "response.output_item.added", "response.function_call_arguments.delta",
				"response.function_call_arguments.done", "response.output_item.done", "response.completed"), ToolReply,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			res := f.do("POST", tc.path, tc.body, tc.hdr...)
			if res.StatusCode != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
				t.Fatalf("%d %s", res.StatusCode, res.Header.Get("Content-Type"))
			}
			evs, err := readSSE(t, res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if got := types(t, evs); !slices.Equal(got, tc.want) {
				t.Fatalf("events\n got %v\nwant %v", got, tc.want)
			}
			if got := text(t, evs); got != tc.text {
				t.Fatalf("text %q, want %q", got, tc.text)
			}
		})
	}
}

// Covers: F985
func TestStreamUsage(t *testing.T) {
	f := newFixture(t)
	body := `{"model":"m","max_tokens":5,"stream":true,"messages":[{"role":"user","content":"hi"}]}`
	in := (int64(len(body)) + 3) / 4
	evs, err := readSSE(t, f.do("POST", "/v1/messages", body, anthropicHdr()...).Body)
	if err != nil {
		t.Fatal(err)
	}
	start, delta := evs[0].json(t), evs[len(evs)-2].json(t)
	if num(path(start, "message", "usage", "input_tokens")) != in || num(path(start, "message", "usage", "output_tokens")) != 1 ||
		num(path(delta, "usage", "output_tokens")) != 5 || num(path(delta, "usage", "input_tokens")) != in || path(delta, "delta", "stop_reason") != "end_turn" {
		t.Fatalf("usage start %v delta %v", start, delta)
	}

	body = `{"model":"m","stream":true,"stream_options":{"include_usage":true},"max_completion_tokens":3,"messages":[]}`
	evs, err = readSSE(t, f.do("POST", "/v1/chat/completions", body, openaiHdr()...).Body)
	if err != nil {
		t.Fatal(err)
	}
	u := evs[len(evs)-2].json(t)
	in = (int64(len(body)) + 3) / 4
	if num(path(u, "usage", "prompt_tokens")) != in || num(path(u, "usage", "completion_tokens")) != 3 {
		t.Fatalf("%v", u)
	}
	if first := evs[0].json(t); !slices.Contains(keys(first), "usage") || first["usage"] != nil {
		t.Fatalf("chunks before the last carry usage null: %v", first)
	}

	body = `{"model":"m","stream":true,"input":"hi","max_output_tokens":4}`
	evs, err = readSSE(t, f.do("POST", "/v1/responses", body, openaiHdr()...).Body)
	if err != nil {
		t.Fatal(err)
	}
	done := evs[len(evs)-1].json(t)
	in = (int64(len(body)) + 3) / 4
	if num(path(done, "response", "usage", "input_tokens")) != in || num(path(done, "response", "usage", "output_tokens")) != 4 ||
		path(done, "response", "status") != "completed" {
		t.Fatalf("%v", done)
	}
	for i, e := range evs {
		if num(e.json(t)["sequence_number"]) != int64(i) {
			t.Fatalf("event %d sequence %v", i, e.json(t)["sequence_number"])
		}
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Covers: F985
func TestSimCutDropsTheAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		path, body string
		hdr        []string
		lastName   string
	}{
		"anthropic stream": {"/v1/messages", `{"model":"sim-cut","max_tokens":5,"stream":true,"messages":[]}`, anthropicHdr(), "content_block_delta"},
		"chat stream":      {"/v1/chat/completions", `{"model":"sim-cut","stream":true,"messages":[]}`, openaiHdr(), ""},
		"responses stream": {"/v1/responses", `{"model":"sim-cut","stream":true,"input":"x"}`, openaiHdr(), "response.output_text.delta"},
		"anthropic body":   {"/v1/messages", `{"model":"sim-cut","max_tokens":5,"messages":[]}`, anthropicHdr(), ""},
		"chat body":        {"/v1/chat/completions", `{"model":"sim-cut","messages":[]}`, openaiHdr(), ""},
		"responses body":   {"/v1/responses", `{"model":"sim-cut","input":"x"}`, openaiHdr(), ""},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			res := f.do("POST", tc.path, tc.body, tc.hdr...)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status %d", res.StatusCode)
			}
			raw, err := res.raw, res.readErr
			if err == nil {
				t.Fatalf("the answer ended cleanly: %s", raw)
			}
			if !strings.HasSuffix(name, "stream") {
				if len(raw) == 0 || int64(len(raw)) >= res.ContentLength {
					t.Fatalf("read %d of %d", len(raw), res.ContentLength)
				}
				return
			}
			evs, _ := readSSE(t, bytes.NewReader(raw))
			last := evs[len(evs)-1]
			if last.name != tc.lastName || text(t, evs) != "SIMULATED" {
				t.Fatalf("cut after %q with text %q", last.name, text(t, evs))
			}
		})
	}
}

// Covers: F985
func TestFaultsAndStats(t *testing.T) {
	f := newFixture(t)
	res := f.do("POST", "/__sim/faults", `{"status":429}`)
	if res.StatusCode != http.StatusNoContent {
		t.Fatal(res.StatusCode)
	}
	res = f.do("POST", "/v1/messages", `{"model":"m","max_tokens":1,"messages":[]}`, anthropicHdr()...)
	if m := decode(t, res); res.StatusCode != http.StatusTooManyRequests || res.Header.Get("Retry-After") != "1" || path(m, "error", "type") != "rate_limit_error" {
		t.Fatalf("%d %v", res.StatusCode, m)
	}
	res = f.do("POST", "/v1/responses", `{"model":"m","input":"x"}`, openaiHdr()...)
	if m := decode(t, res); res.StatusCode != http.StatusTooManyRequests || path(m, "error", "code") != "rate_limit_exceeded" {
		t.Fatalf("%d %v", res.StatusCode, m)
	}
	f.sim.SetFaults(Faults{StreamDelayMS: 1})
	prompt := "a prompt the simulator must never keep"
	body := `{"model":"sim-model","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"` + prompt + `"}]}`
	evs, err := readSSE(t, f.do("POST", "/v1/messages", body, anthropicHdr()...).Body)
	if err != nil || len(evs) != 8 {
		t.Fatalf("%v %d", err, len(evs))
	}
	sum := sha256.Sum256([]byte(body))
	raw, err := io.ReadAll(f.do("GET", "/__sim/stats", "").Body)
	if err != nil {
		t.Fatal(err)
	}
	var st Stats
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.LastBodySHA256 != hex.EncodeToString(sum[:]) || st.LastModel != ModelDefault || st.Calls[OpMessages] != 2 || st.Calls[OpResponses] != 1 || st.Requests != 3 {
		t.Fatalf("%+v", st)
	}
	if strings.Contains(string(raw), prompt) || strings.Contains(string(raw), "messages\":[") {
		t.Fatal("the stats hold a body")
	}
	if res := f.do("POST", "/__sim/faults", `{"status":"x"}`); res.StatusCode != http.StatusBadRequest {
		t.Fatal(res.StatusCode)
	}
}

// Covers: F985
func TestUnknownRouteAndOversizeBody(t *testing.T) {
	f := newFixture(t)
	res := f.do("POST", "/v1/completions", `{}`, openaiHdr()...)
	if m := decode(t, res); res.StatusCode != http.StatusNotFound || path(m, "error", "type") != "invalid_request_error" {
		t.Fatalf("%d %v", res.StatusCode, m)
	}
	res = f.do("GET", "/v2/models", "", anthropicHdr()...)
	if m := decode(t, res); res.StatusCode != http.StatusNotFound || path(m, "error", "type") != "not_found_error" {
		t.Fatalf("%d %v", res.StatusCode, m)
	}
	if maxBody != 32<<20 {
		t.Fatalf("the simulator's body limit is %d, want twice the gateway's 16 MiB", maxBody)
	}
	f.sim.limit = 64
	big := `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"` + strings.Repeat("a", 64) + `"}]}`
	res = f.do("POST", "/v1/messages", big, anthropicHdr()...)
	if m := decode(t, res); res.StatusCode != http.StatusRequestEntityTooLarge || path(m, "error", "type") != "request_too_large" {
		t.Fatalf("%d %v", res.StatusCode, m)
	}
}
