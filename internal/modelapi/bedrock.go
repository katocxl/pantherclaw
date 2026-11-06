// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelapi

import (
	"bytes"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strconv"
)

// The bedrock_converse format (G0 M31 D961): Amazon Bedrock's Converse and
// ConverseStream. The model is in the path. The max output tokens are
// inferenceConfig.maxTokens; tools are toolConfig.tools[], each one object
// with one member naming its kind (toolSpec: a tool the agent runs); a
// stream is an AWS event stream (application/vnd.amazon.eventstream), whose
// metadata event carries the usage.

// bedrockMaxTokens names Bedrock's max output tokens for the action and
// refusals (inferenceConfig.maxTokens).
const bedrockMaxTokens = "inferenceConfig.maxTokens"

// Bedrock tool entries that are not provider-side tools: a tool the agent
// runs (toolSpec) and a prompt cache marker (cachePoint).
var bedrockClientEntries = []string{"toolSpec", "cachePoint"}

// extractBedrock reads a Converse request's max tokens and the
// provider-side tools it names (G0 M31 D961, HR-696). An unknown tool entry
// counts as provider-side (fail closed); Anthropic tools passed through
// additionalModelRequestFields.tools are classified as on the Messages API.
func (r *Request) extractBedrock(top map[string]jsontext.Value) error {
	if r.API.StreamPath() {
		r.Stream = true
	}
	if v, ok := top["inferenceConfig"]; ok && v.Kind() != 'n' {
		cfg := object(v)
		if cfg == nil {
			return fail(CodeInvalidRequest, "inferenceConfig must be an object")
		}
		if mt, ok := cfg["maxTokens"]; ok && mt.Kind() != 'n' {
			n, err := integer("inferenceConfig.maxTokens", mt, 1, MaxTokens)
			if err != nil {
				return err
			}
			r.MaxTokens = n
		}
	}
	names := map[string]bool{}
	if v, ok := top["toolConfig"]; ok && v.Kind() != 'n' {
		cfg := object(v)
		if cfg == nil {
			return fail(CodeInvalidRequest, "toolConfig must be an object")
		}
		if t, ok := cfg["tools"]; ok && t.Kind() != 'n' {
			var tools []map[string]jsontext.Value
			if err := json.Unmarshal(t, &tools); err != nil {
				return fail(CodeInvalidRequest, "toolConfig.tools must be an array of objects")
			}
			for _, tool := range tools {
				if len(tool) != 1 {
					return fail(CodeInvalidRequest, "a tool names exactly one kind")
				}
				for kind := range tool {
					if !slices.Contains(bedrockClientEntries, kind) {
						names[kind] = true
					}
				}
			}
		}
	}
	if v, ok := top["additionalModelRequestFields"]; ok && v.Kind() != 'n' {
		extra := object(v)
		if extra == nil {
			return fail(CodeInvalidRequest, "additionalModelRequestFields must be an object")
		}
		if t, ok := extra["tools"]; ok && t.Kind() != 'n' {
			var tools []map[string]jsontext.Value
			if err := json.Unmarshal(t, &tools); err != nil {
				return fail(CodeInvalidRequest, "additionalModelRequestFields.tools must be an array of objects")
			}
			anth := &Request{API: AnthropicMessages}
			for _, tool := range tools {
				var name string
				typ, set := tool["type"]
				if set && typ.Kind() != 'n' {
					if typ.Kind() != '"' || json.Unmarshal(typ, &name) != nil || name == "" {
						return fail(CodeInvalidRequest, "a tool's type must be a non-empty string")
					}
				}
				if anth.providerSide(name, set && typ.Kind() != 'n') {
					names[name] = true
				}
			}
		}
	}
	if len(names) > MaxServerTools {
		return fail(CodeInvalidRequest, "at most %d provider-side tools", MaxServerTools)
	}
	r.ServerTools = make([]string, 0, len(names))
	for n := range names {
		r.ServerTools = append(r.ServerTools, n)
	}
	slices.Sort(r.ServerTools)
	return nil
}

// insertBedrockMaxTokens adds inferenceConfig.maxTokens to a compact
// Converse body that has none: into its inferenceConfig object when there
// is one, else as a new last member {"inferenceConfig":{"maxTokens":n}}.
// The other members keep their order and bytes.
func insertBedrockMaxTokens(body []byte, n int64) ([]byte, error) {
	if n < 1 || n > MaxTokens {
		return nil, fail(CodeInvalidRequest, "default max tokens out of range")
	}
	member := `"maxTokens":` + strconv.FormatInt(n, 10)
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, fail(CodeInvalidJSON, "the body must be a JSON object")
	}
	var out bytes.Buffer
	out.WriteByte('{')
	found, first := false, true
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, fail(CodeInvalidJSON, "the body is not one strict JSON object")
		}
		// The token is voided by the next read: keep its name first.
		name := tok.String()
		v, err := dec.ReadValue()
		if err != nil {
			return nil, fail(CodeInvalidJSON, "the body is not one strict JSON object")
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		key, _ := jsontext.AppendQuote(nil, name)
		out.Write(key)
		out.WriteByte(':')
		if name == "inferenceConfig" && v.Kind() == '{' {
			found = true
			inner := bytes.TrimSuffix([]byte(v), []byte("}"))
			out.Write(inner)
			if len(inner) > 1 {
				out.WriteByte(',')
			}
			out.WriteString(member + "}")
			continue
		}
		if name == "inferenceConfig" && v.Kind() == 'n' {
			found = true
			out.WriteString("{" + member + "}")
			continue
		}
		out.Write(v)
	}
	if !found {
		if !first {
			out.WriteByte(',')
		}
		out.WriteString(`"inferenceConfig":{` + member + "}")
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// EventStream reads a Bedrock ConverseStream answer as it passes (G0 M31
// D961): AWS event stream frames, each a 12-byte prelude (total length,
// headers length, prelude CRC), headers, a JSON payload and a message CRC.
// An exception frame is an error; the metadata event, the last one, ends
// the stream and carries the usage. It keeps at most one frame.
type EventStream struct {
	api      API
	buf      []byte
	usage    Usage
	lost     bool
	complete bool
	errored  bool
}

// NewEventStream starts reading a Bedrock event stream.
func NewEventStream(api API) *EventStream { return &EventStream{api: api} }

// Write feeds the next bytes of the stream; it never fails.
func (s *EventStream) Write(p []byte) (int, error) {
	n := len(p)
	if s.lost {
		return n, nil
	}
	s.buf = append(s.buf, p...)
	for len(s.buf) >= 12 {
		total := int(binary.BigEndian.Uint32(s.buf[0:4]))
		hlen := int(binary.BigEndian.Uint32(s.buf[4:8]))
		if total < 16 || total > MaxEvent || hlen > total-16 {
			// Not a frame, or one too large to read: usage unreported.
			s.lost, s.buf = true, nil
			return n, nil
		}
		if len(s.buf) < total {
			break
		}
		s.frame(s.buf[12:12+hlen], s.buf[12+hlen:total-4])
		s.buf = s.buf[total:]
	}
	return n, nil
}

// frame handles one complete frame.
func (s *EventStream) frame(headers, payload []byte) {
	h, ok := eventHeaders(headers)
	if !ok {
		s.lost = true
		return
	}
	if h[":message-type"] == "exception" || h[":message-type"] == "error" {
		s.errored = true
		return
	}
	if h[":event-type"] != "metadata" {
		return
	}
	s.complete = true
	if u, ok := usageOf(s.api, object(object(jsontext.Value(payload))["usage"])); ok {
		s.usage = u
	}
}

// eventHeaders reads a frame's string headers; ok is false for headers
// that do not parse.
func eventHeaders(b []byte) (map[string]string, bool) {
	out := map[string]string{}
	for len(b) > 0 {
		nl := int(b[0])
		if len(b) < 1+nl+1 {
			return nil, false
		}
		name := string(b[1 : 1+nl])
		typ := b[1+nl]
		b = b[2+nl:]
		var size int
		switch typ {
		case 0, 1: // true, false
		case 2: // byte
			size = 1
		case 3: // short
			size = 2
		case 4: // int
			size = 4
		case 5, 8: // long, timestamp
			size = 8
		case 9: // uuid
			size = 16
		case 6, 7: // bytes, string
			if len(b) < 2 {
				return nil, false
			}
			size = 2 + int(binary.BigEndian.Uint16(b[:2]))
		default:
			return nil, false
		}
		if len(b) < size {
			return nil, false
		}
		if typ == 7 {
			out[name] = string(b[2:size])
		}
		b = b[size:]
	}
	return out, true
}

// Usage is the usage the stream reported; unreported when it had none or a
// frame could not be read.
func (s *EventStream) Usage() Usage {
	if s.lost || !s.usage.Reported {
		return Usage{}
	}
	return s.usage
}

// Complete reports whether the stream reached its metadata event.
func (s *EventStream) Complete() bool { return s.complete && !s.lost }

// Errored reports whether the stream carried an exception.
func (s *EventStream) Errored() bool { return s.errored }
