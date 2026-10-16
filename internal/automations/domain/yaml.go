// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	maxYAMLDepth  = 24
	maxStringLen  = 4096
	maxYAMLSource = 4 * MaxDefinitionBytes
)

var plainInt = regexp.MustCompile(`^(0|-?[1-9][0-9]{0,17})$`)

// yamlToJSON converts an authored YAML definition to JSON: one document, a
// mapping at the top, no anchors, aliases, tags, merge keys or nulls;
// decimals are quoted strings.
func yamlToJSON(raw []byte) ([]byte, error) {
	switch {
	case len(raw) > maxYAMLSource:
		return nil, invalid("size %d over %d bytes", len(raw), maxYAMLSource)
	case !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) || bytes.IndexByte(raw, 0) >= 0:
		return nil, invalid("a definition is UTF-8 without a byte order mark or NUL bytes")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, invalid("%v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalid("a definition holds exactly one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, invalid("the document must be a mapping")
	}
	var out bytes.Buffer
	enc := jsontext.NewEncoder(&out)
	if err := convertYAML(enc, doc.Content[0], 1); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(out.Bytes()), nil
}

func convertYAML(enc *jsontext.Encoder, n *yaml.Node, depth int) error {
	at := fmt.Sprintf("line %d", n.Line)
	switch {
	case depth > maxYAMLDepth:
		return invalid("%s: nesting deeper than %d", at, maxYAMLDepth)
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
			if len(k.Value) > maxStringLen {
				return invalid("line %d: key longer than %d bytes", k.Line, maxStringLen)
			}
			if err := enc.WriteToken(jsontext.String(k.Value)); err != nil {
				return invalid("line %d: %v", k.Line, err)
			}
			if err := convertYAML(enc, n.Content[i+1], depth+1); err != nil {
				return err
			}
		}
		return yamlTokenErr(at, enc.WriteToken(jsontext.EndObject))
	case yaml.SequenceNode:
		if err := enc.WriteToken(jsontext.BeginArray); err != nil {
			return invalid("%s: %v", at, err)
		}
		for _, c := range n.Content {
			if err := convertYAML(enc, c, depth+1); err != nil {
				return err
			}
		}
		return yamlTokenErr(at, enc.WriteToken(jsontext.EndArray))
	case yaml.ScalarNode:
		return yamlScalar(enc, n, at)
	case yaml.DocumentNode, yaml.AliasNode:
	}
	return invalid("%s: unexpected YAML node", at)
}

func yamlScalar(enc *jsontext.Encoder, n *yaml.Node, at string) error {
	switch n.Tag {
	case "!!str", "!!timestamp":
		if len(n.Value) > maxStringLen {
			return invalid("%s: string longer than %d bytes", at, maxStringLen)
		}
		return yamlTokenErr(at, enc.WriteToken(jsontext.String(n.Value)))
	case "!!bool":
		if n.Value != "true" && n.Value != "false" {
			return invalid("%s: booleans are written true or false", at)
		}
		return yamlTokenErr(at, enc.WriteToken(jsontext.Bool(n.Value == "true")))
	case "!!int":
		if !plainInt.MatchString(n.Value) {
			return invalid("%s: integers are plain decimal (quote other numbers as strings)", at)
		}
		return yamlTokenErr(at, enc.WriteValue(jsontext.Value(n.Value)))
	case "!!null":
		return invalid("%s: null or empty values are not allowed; omit the field", at)
	default:
		return invalid("%s: %s values are not allowed (quote decimals as strings)", at, n.Tag)
	}
}

func yamlTokenErr(at string, err error) error {
	if err != nil {
		return invalid("%s: %v", at, err)
	}
	return nil
}
