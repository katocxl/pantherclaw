// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// MaxDepth bounds YAML nesting.
const MaxDepth = 24

// ErrInvalid reports a scenario file that cannot be decoded strictly (HR-223).
var ErrInvalid = errors.New("redteam: invalid scenario file")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Parse decodes and validates one scenario file. The file is data: one YAML
// document, no anchors, aliases, tags or merge keys, converted to JSON and
// decoded rejecting unknown members; then Validate checks the closed
// catalog. The caller compares the filename with the id (ValidateFileName).
func Parse(raw []byte) (*Scenario, error) {
	doc, err := ToJSON(raw)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := json.Unmarshal(doc, &s, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("%v", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

var plainInt = regexp.MustCompile(`^(0|-?[1-9][0-9]{0,17})$`)

// ToJSON converts a YAML scenario file to JSON under the strict rules.
func ToJSON(raw []byte) ([]byte, error) {
	switch {
	case len(raw) == 0 || len(raw) > MaxFileBytes:
		return nil, invalid("size %d outside 1..%d bytes", len(raw), MaxFileBytes)
	case !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) || bytes.IndexByte(raw, 0) >= 0:
		return nil, invalid("a scenario file is UTF-8 without a byte order mark or NUL bytes")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, invalid("%v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalid("a scenario file holds exactly one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, invalid("the document must be a mapping")
	}
	var out bytes.Buffer
	enc := jsontext.NewEncoder(&out)
	if err := convert(enc, doc.Content[0], 1); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

func convert(enc *jsontext.Encoder, n *yaml.Node, depth int) error {
	at := fmt.Sprintf("line %d", n.Line)
	switch {
	case depth > MaxDepth:
		return invalid("%s: nesting deeper than %d", at, MaxDepth)
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		return invalid("%s: anchors and aliases are not allowed", at)
	case n.Style&yaml.TaggedStyle != 0:
		return invalid("%s: explicit tags are not allowed", at)
	}
	switch n.Kind {
	case yaml.MappingNode:
		if err := enc.WriteToken(jsontext.BeginObject); err != nil {
			return invalid("%s: %v", at, err)
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
				return invalid("line %d: keys must be plain strings (no merge keys)", k.Line)
			}
			if seen[k.Value] {
				return invalid("line %d: duplicate key %q", k.Line, k.Value)
			}
			seen[k.Value] = true
			if len(k.Value) > MaxStringLen {
				return invalid("line %d: key longer than %d bytes", k.Line, MaxStringLen)
			}
			if err := enc.WriteToken(jsontext.String(k.Value)); err != nil {
				return invalid("line %d: %v", k.Line, err)
			}
			if err := convert(enc, n.Content[i+1], depth+1); err != nil {
				return err
			}
		}
		return tokenErr(at, enc.WriteToken(jsontext.EndObject))
	case yaml.SequenceNode:
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return invalid("%s: %v", at, err)
		}
		for _, c := range n.Content {
			if err := convert(enc, c, depth+1); err != nil {
				return err
			}
		}
		return tokenErr(at, enc.WriteToken(jsontext.EndArray))
	case yaml.ScalarNode:
		return scalar(enc, n, at)
	case yaml.DocumentNode, yaml.AliasNode:
	}
	return invalid("%s: unexpected YAML node", at)
}

func scalar(enc *jsontext.Encoder, n *yaml.Node, at string) error {
	switch n.Tag {
	case "!!str", "!!timestamp":
		if len(n.Value) > MaxStringLen {
			return invalid("%s: string longer than %d bytes", at, MaxStringLen)
		}
		return tokenErr(at, enc.WriteToken(jsontext.String(n.Value)))
	case "!!bool":
		if n.Value != "true" && n.Value != "false" {
			return invalid("%s: booleans are written true or false", at)
		}
		return tokenErr(at, enc.WriteToken(jsontext.Bool(n.Value == "true")))
	case "!!int":
		if !plainInt.MatchString(n.Value) {
			return invalid("%s: integers are plain decimal (quote other numbers as strings)", at)
		}
		return tokenErr(at, enc.WriteValue(jsontext.Value(n.Value)))
	case "!!null":
		return invalid("%s: null or empty values are not allowed; omit the field", at)
	default:
		return invalid("%s: %s values are not allowed (quote decimals as strings)", at, n.Tag)
	}
}

func tokenErr(at string, err error) error {
	if err != nil {
		return invalid("%s: %v", at, err)
	}
	return nil
}
