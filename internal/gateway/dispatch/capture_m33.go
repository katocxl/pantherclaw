// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"io"
	"slices"
	"strconv"
)

// Prompt capture without images (G0 M33 D985, HR-757): before a model
// request body is kept as a capture, every image, document, audio or
// screenshot block in it is replaced by
// {"type":"<original>","omitted":true,"bytes":N,"sha256":"<hex>"}, N and
// the digest those of the block's raw JSON, and the text is kept. A body
// that cannot be parsed is not kept: its capture says omitted. Neither is a
// body nested deeper than maxCaptureDepth: its capture says omitted with
// reason too_deep (D1221 H1).
//
// The body is read in one streaming pass that records only the byte ranges
// of the blocks to omit, then copied once with those ranges replaced, so
// memory stays proportional to the body whatever its nesting (D1221 H1).

// omittedTypes are the block types a capture never keeps: Anthropic image,
// document and container_upload blocks (at any depth, tool_result content
// included), Chat image_url, file and input_audio parts, and Responses
// input_image and input_file items (D1221 M4).
var omittedTypes = map[string]bool{
	"image": true, "document": true, "container_upload": true,
	"image_url": true, "file": true, "input_audio": true,
	"input_image": true, "input_file": true,
}

// computerOutputType is the Responses item whose output (a screenshot) is
// never kept.
const computerOutputType = "computer_call_output"

// bedrockMedia are the Bedrock Converse content blocks a capture never
// keeps (G0 M33 D985a): an object whose only member is one of these, with
// an object value holding source, at any depth (toolResult content
// included).
var bedrockMedia = map[string]bool{"image": true, "document": true, "video": true}

// maxCaptureDepth is the deepest nesting a captured body may have; a
// deeper body is stored as omitted with reason too_deep (D1221 H1).
const maxCaptureDepth = 64

// omitRange is one block to omit: body[start:end] becomes the placeholder
// of type typ.
type omitRange struct {
	start, end int64
	typ        string
}

// captureFrame is one open object or array of the walk.
type captureFrame struct {
	start    int64
	object   bool
	wantName bool
	member   string // the current member's name (objects)
	members  int
	first    string // the first member's name
	// firstSource: the first member's value is an object holding source.
	firstSource bool
	typ         string // the object's string "type" member
	// hasSource: the object has a member named source.
	hasSource bool
	// The range of the "output" member's value, and that value's type.
	outputSet              bool
	outputStart, outputEnd int64
	outputType             string
}

// withoutImages returns body with every omitted block replaced, or false
// when body is not one JSON value. A body nested deeper than
// maxCaptureDepth comes back as its omitted form with reason too_deep.
func withoutImages(body []byte) ([]byte, bool) {
	reps, tooDeep, ok := omittedRanges(body)
	switch {
	case !ok:
		return nil, false
	case tooDeep:
		return omittedBodyReason(len(body), "too_deep"), true
	case len(reps) == 0:
		return body, true
	}
	out := make([]byte, 0, len(body))
	var at int64
	for _, r := range reps {
		ph, err := placeholder(r.typ, body[r.start:r.end])
		if err != nil {
			return nil, false
		}
		out = append(append(out, body[at:r.start]...), ph...)
		at = r.end
	}
	return append(out, body[at:]...), true
}

// omittedRanges walks body once and returns the outermost blocks to omit
// in order, whether body is nested deeper than maxCaptureDepth, and false
// when body is not exactly one JSON value.
func omittedRanges(body []byte) ([]omitRange, bool, bool) {
	dec := jsontext.NewDecoder(bytes.NewBuffer(body))
	var (
		stack []*captureFrame
		reps  []omitRange
		done  bool
	)
	// closed records a finished value with its parent: its range, and its
	// frame when it was a container.
	closed := func(start, end int64, f *captureFrame) {
		if len(stack) == 0 {
			done = true
			return
		}
		p := stack[len(stack)-1]
		if !p.object {
			return
		}
		if p.member == "output" {
			p.outputSet, p.outputStart, p.outputEnd = true, start, end
			p.outputType = ""
			if f != nil && f.object {
				p.outputType = f.typ
			}
		}
		if p.members == 1 && f != nil && f.object && f.hasSource {
			p.firstSource = true
		}
		p.wantName = true
	}
	for {
		k := dec.PeekKind()
		if k == 0 {
			_, err := dec.ReadToken()
			if !errors.Is(err, io.EOF) || !done {
				return nil, false, false
			}
			break
		}
		if done {
			return nil, false, false // a second top-level value
		}
		var top *captureFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.wantName && k != '}' {
			tok, err := dec.ReadToken()
			if err != nil {
				return nil, false, false
			}
			// A token is valid only until the decoder's next read.
			name := tok.String()
			top.member, top.wantName = name, false
			top.members++
			if top.members == 1 {
				top.first = name
			}
			if name == "source" {
				top.hasSource = true
			}
			continue
		}
		start := valueStart(body, dec.InputOffset())
		switch k { //nolint:exhaustive // Containers are walked; every other kind is one scalar value.
		case '{', '[':
			if _, err := dec.ReadToken(); err != nil {
				return nil, false, false
			}
			if dec.StackDepth() > maxCaptureDepth {
				return nil, true, true
			}
			stack = append(stack, &captureFrame{start: start, object: k == '{', wantName: k == '{'})
		case '}', ']':
			if _, err := dec.ReadToken(); err != nil {
				return nil, false, false
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			end := dec.InputOffset()
			if f.object {
				switch {
				case omittedTypes[f.typ]:
					reps = append(reps, omitRange{f.start, end, f.typ})
				case f.members == 1 && bedrockMedia[f.first] && f.firstSource:
					reps = append(reps, omitRange{f.start, end, f.first})
				case f.typ == computerOutputType && f.outputSet:
					reps = append(reps, omitRange{f.outputStart, f.outputEnd, cmp.Or(f.outputType, "output")})
				}
			}
			closed(f.start, end, f)
		default:
			if top != nil && top.object && top.member == "type" && k == '"' {
				tok, err := dec.ReadToken()
				if err != nil {
					return nil, false, false
				}
				top.typ = tok.String()
			} else if err := dec.SkipValue(); err != nil {
				return nil, false, false
			}
			closed(start, dec.InputOffset(), nil)
		}
	}
	return outermost(reps), false, true
}

// valueStart is the offset of the value that follows at: the separators
// and whitespace after the previous token are skipped.
func valueStart(body []byte, at int64) int64 {
	for at < int64(len(body)) {
		switch body[at] {
		case ' ', '\t', '\r', '\n', ',', ':':
			at++
		default:
			return at
		}
	}
	return at
}

// outermost sorts ranges by position and drops every range inside an
// earlier one: an omitted block is omitted whole.
func outermost(reps []omitRange) []omitRange {
	slices.SortFunc(reps, func(a, b omitRange) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(b.end, a.end))
	})
	out := reps[:0]
	var end int64 = -1
	for _, r := range reps {
		if r.start < end {
			continue
		}
		out = append(out, r)
		end = r.end
	}
	return out
}

// omittedBody is what a capture keeps of a body it cannot parse.
func omittedBody(size int) []byte {
	return []byte(`{"omitted":true,"bytes":` + strconv.Itoa(size) + `}`)
}

// omittedBodyReason is omittedBody with the reason the body was not kept.
func omittedBodyReason(size int, reason string) []byte {
	return []byte(`{"omitted":true,"bytes":` + strconv.Itoa(size) + `,"reason":"` + reason + `"}`)
}

// placeholder is the omitted form of raw, a block of type typ.
func placeholder(typ string, raw []byte) ([]byte, error) {
	sum := sha256.Sum256(raw)
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	for _, t := range []jsontext.Token{
		jsontext.BeginObject,
		jsontext.String("type"), jsontext.String(typ),
		jsontext.String("omitted"), jsontext.True,
		jsontext.String("bytes"), jsontext.Int(int64(len(raw))),
		jsontext.String("sha256"), jsontext.String(hex.EncodeToString(sum[:])),
		jsontext.EndObject,
	} {
		if err := enc.WriteToken(t); err != nil {
			return nil, err
		}
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}
