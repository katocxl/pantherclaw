// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package manifest decodes tool package files (YAML, format 1).
//
// YAML is decoded into a node tree and converted to JSON under strict rules
// (HR-100): one document only; no anchors, aliases, merge keys or explicit
// tags; string keys only, never duplicated; no nulls or floats; integers
// only in plain decimal form; depth and size limits. The JSON is then
// decoded with encoding/json/v2, rejecting unknown fields, and validated.
//
// Two digests come out of a package file:
//   - the file digest, SHA-256 of the exact bytes, which the signed targets
//     metadata lists (internal/definitions/trust), so no parser
//     differential can change what was signed;
//   - one digest per definition, SHA-256 of the RFC 8785 canonical JSON of
//     that definition (mappings included), which ActionIR pins and approvals
//     bind.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// Limits.
const (
	MaxBytes = 1 << 20
	MaxDepth = 32
)

// ErrInvalid reports a package file that cannot be decoded strictly.
var ErrInvalid = errors.New("manifest: invalid package file")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// FileDigest returns "sha256:<hex>" of the exact package bytes.
func FileDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Decode parses, validates and digests a package file.
func Decode(raw []byte) (*domain.Package, error) {
	doc, err := ToJSON(raw)
	if err != nil {
		return nil, err
	}
	var p domain.Package
	if err := json.Unmarshal(doc, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("%v", err)
	}
	canon, err := canonicalDefinitions(doc)
	if err != nil || len(canon) != len(p.Definitions) {
		return nil, invalid("definitions: %v", err)
	}
	for i, c := range canon {
		sum := sha256.Sum256(c)
		p.Definitions[i].Digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	// Each declared elicitation field becomes a material param (G0 M15 D32).
	p.ExpandElicitation()
	return &p, nil
}

// Canonical returns the RFC 8785 canonical JSON form of a package file.
func Canonical(raw []byte) ([]byte, error) {
	doc, err := ToJSON(raw)
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(doc)
	if err := v.Canonicalize(); err != nil {
		return nil, invalid("%v", err)
	}
	return v, nil
}

var plainInt = regexp.MustCompile(`^(0|-?[1-9][0-9]{0,17})$`)

// ToJSON converts a YAML package file to JSON under the strict rules.
func ToJSON(raw []byte) ([]byte, error) {
	switch {
	case len(raw) == 0 || len(raw) > MaxBytes:
		return nil, invalid("size %d outside 1..%d bytes", len(raw), MaxBytes)
	case !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) || bytes.IndexByte(raw, 0) >= 0:
		return nil, invalid("a package file is UTF-8 without a byte order mark or NUL bytes")
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, invalid("%v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, invalid("a package file holds exactly one YAML document")
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
	case "!!str", "!!timestamp": // dates stay strings; the domain parses them
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

// DefinitionsCanonical returns the RFC 8785 canonical JSON of each
// definition of a package file, in file order: the exact bytes whose
// SHA-256 is the definition digest.
func DefinitionsCanonical(raw []byte) ([][]byte, error) {
	doc, err := ToJSON(raw)
	if err != nil {
		return nil, err
	}
	return canonicalDefinitions(doc)
}

func canonicalDefinitions(doc []byte) ([][]byte, error) {
	var parts struct {
		Definitions []jsontext.Value `json:"definitions"`
	}
	if err := json.Unmarshal(doc, &parts); err != nil {
		return nil, invalid("definitions: %v", err)
	}
	out := make([][]byte, len(parts.Definitions))
	for i, d := range parts.Definitions {
		c := bytes.Clone(d)
		if err := (*jsontext.Value)(&c).Canonicalize(); err != nil {
			return nil, invalid("definitions[%d]: %v", i, err)
		}
		out[i] = c
	}
	return out, nil
}
