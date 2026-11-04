// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelapi

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
)

// MaxUsageCount bounds each reported count (the ModelUsage message's range).
const MaxUsageCount = 1_000_000_000

// MaxEvent is the largest stream event whose data is read for usage: the
// answer cap, so any event that fits in the answer is read (G0 M29 D873).
const MaxEvent = MaxBody

// Usage is a call's token usage as the provider reported it, normalized
// (D818): OpenAI's cached tokens are part of its prompt or input tokens, so
// they count in CacheRead and not in Input.
type Usage struct {
	Input, Output, CacheRead, CacheWrite int64
	// Reported is whether the answer carried usage.
	Reported bool
}

// Total is the four counts summed.
func (u Usage) Total() int64 { return u.Input + u.Output + u.CacheRead + u.CacheWrite }

// count reads one usage member: a non-negative integer of at most
// MaxUsageCount; ok is false for anything else. An absent member is 0.
func count(obj map[string]jsontext.Value, name string) (int64, bool) {
	v, set := obj[name]
	if !set || v.Kind() == 'n' {
		return 0, true
	}
	if v.Kind() != '0' {
		return 0, false
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil || n < 0 || n > MaxUsageCount {
		return 0, false
	}
	return n, true
}

// object decodes v as a JSON object; nil when it is not one.
func object(v jsontext.Value) map[string]jsontext.Value {
	if v.Kind() != '{' {
		return nil
	}
	var m map[string]jsontext.Value
	if json.Unmarshal(v, &m) != nil {
		return nil
	}
	return m
}

// usageOf normalizes one usage object of api; ok is false when it is not a
// usage object of that API's shape.
func usageOf(api API, u map[string]jsontext.Value) (Usage, bool) {
	if u == nil {
		return Usage{}, false
	}
	var out Usage
	oks := make([]bool, 0, 4)
	read := func(dst *int64, obj map[string]jsontext.Value, name string) {
		n, ok := count(obj, name)
		*dst = n
		oks = append(oks, ok)
	}
	switch {
	case api.Anthropic():
		read(&out.Input, u, "input_tokens")
		read(&out.Output, u, "output_tokens")
		read(&out.CacheRead, u, "cache_read_input_tokens")
		read(&out.CacheWrite, u, "cache_creation_input_tokens")
	default:
		in, details := "input_tokens", "input_tokens_details"
		if api == OpenAIChat {
			in, details = "prompt_tokens", "prompt_tokens_details"
			read(&out.Output, u, "completion_tokens")
		} else {
			read(&out.Output, u, "output_tokens")
		}
		read(&out.Input, u, in)
		if d, set := u[details]; set && d.Kind() != 'n' {
			read(&out.CacheRead, object(d), "cached_tokens")
		}
		if out.CacheRead > out.Input {
			return Usage{}, false
		}
		out.Input -= out.CacheRead
	}
	for _, ok := range oks {
		if !ok {
			return Usage{}, false
		}
	}
	out.Reported = true
	return out, true
}

// AnswerUsage reads the top-level usage of a complete JSON answer of api
// (D818). Reported is false when the answer has none or it cannot be read.
func AnswerUsage(api API, body []byte) Usage {
	var top map[string]jsontext.Value
	if json.Unmarshal(body, &top) != nil {
		return Usage{}
	}
	u, _ := usageOf(api, object(top["usage"]))
	return u
}

// Stream reads a server-sent event stream of api as it passes (D818): the
// usage it reports, whether it reached its terminal event, and whether it
// carried an error event. It never keeps the events' text beyond the event
// being read.
type Stream struct {
	api API
	// line is the current line, kept to MaxEvent bytes; event and data
	// are the current event's name and data.
	line      []byte
	lineOver  bool
	event     string
	data      []byte
	dataOver  bool
	usage     Usage
	lost      bool // an event's data was too large to read: usage unreported
	anthStart bool
	complete  bool
	errored   bool
}

// NewStream starts reading a stream of api.
func NewStream(api API) *Stream { return &Stream{api: api} }

// Write feeds the next bytes of the stream; it never fails.
func (s *Stream) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			s.appendLine(p)
			break
		}
		s.appendLine(p[:i])
		s.endLine()
		p = p[i+1:]
	}
	return n, nil
}

func (s *Stream) appendLine(p []byte) {
	if s.lineOver || len(s.line)+len(p) > MaxEvent {
		s.lineOver, s.line = true, s.line[:0]
		return
	}
	s.line = append(s.line, p...)
}

// endLine handles one complete line (SSE: field lines, a blank line ends
// the event).
func (s *Stream) endLine() {
	line := bytes.TrimSuffix(s.line, []byte("\r"))
	over := s.lineOver
	s.line, s.lineOver = s.line[:0], false
	if len(line) == 0 && !over {
		s.dispatch()
		return
	}
	field, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(field) {
	case "event":
		if !over {
			s.event = string(value)
		}
	case "data":
		if over || s.dataOver || len(s.data)+len(value)+1 > MaxEvent {
			s.dataOver, s.data = true, s.data[:0]
			return
		}
		if len(s.data) > 0 {
			s.data = append(s.data, '\n')
		}
		s.data = append(s.data, value...)
	}
}

// dispatch handles one complete event. An event whose data was too large
// is not read: the usage is then unreported, but its name still counts
// (Anthropic and Responses name their terminal and error events).
func (s *Stream) dispatch() {
	event, data, over := s.event, s.data, s.dataOver
	s.event, s.data, s.dataOver = "", s.data[:0], false
	if over {
		s.lost = true
	}
	var top map[string]jsontext.Value
	if !over && len(data) > 0 && !bytes.Equal(data, []byte("[DONE]")) {
		top = object(jsontext.Value(data))
	}
	typ := event
	if v, ok := top["type"]; ok && v.Kind() == '"' {
		_ = json.Unmarshal(v, &typ)
	}
	switch s.api {
	case AnthropicMessages, AnthropicCountTokens:
		s.anthropic(typ, top)
	case OpenAIChat:
		switch {
		case bytes.Equal(data, []byte("[DONE]")):
			s.complete = true
		case top["error"] != nil && top["error"].Kind() != 'n':
			s.errored = true
		default:
			if u, ok := usageOf(OpenAIChat, object(top["usage"])); ok {
				s.usage = u
			}
		}
	case OpenAIResponses:
		switch typ {
		case "error":
			s.errored = true
		case "response.completed":
			s.complete = true
			if u, ok := usageOf(OpenAIResponses, object(object(top["response"])["usage"])); ok {
				s.usage = u
			}
		}
	case AnthropicModels, OpenAIModels:
		// A read is never a stream.
	}
}

// anthropic reads one Messages stream event: message_start carries the
// first usage, each message_delta the cumulative counts so far.
func (s *Stream) anthropic(typ string, top map[string]jsontext.Value) {
	switch typ {
	case "error":
		s.errored = true
	case "message_stop":
		s.complete = true
	case "message_start":
		if u, ok := usageOf(s.api, object(object(top["message"])["usage"])); ok {
			s.usage, s.anthStart = u, true
		}
	case "message_delta":
		d := object(top["usage"])
		if d == nil {
			return
		}
		// Each field present takes its latest value; the others keep theirs.
		next := s.usage
		for name, dst := range map[string]*int64{
			"input_tokens": &next.Input, "output_tokens": &next.Output,
			"cache_read_input_tokens": &next.CacheRead, "cache_creation_input_tokens": &next.CacheWrite,
		} {
			if v, set := d[name]; set && v.Kind() != 'n' {
				n, ok := count(d, name)
				if !ok {
					s.lost = true
					return
				}
				*dst = n
			}
		}
		next.Reported = true
		s.usage = next
	}
}

// Usage is the usage the stream reported so far; unreported when it had
// none or an event was too large to read.
func (s *Stream) Usage() Usage {
	if s.lost || !s.usage.Reported {
		return Usage{}
	}
	return s.usage
}

// Complete reports whether the stream reached its terminal event:
// Anthropic message_stop, OpenAI chat data: [DONE], Responses
// response.completed (D818).
func (s *Stream) Complete() bool { return s.complete }

// Errored reports whether the stream carried an error event.
func (s *Stream) Errored() bool { return s.errored }
