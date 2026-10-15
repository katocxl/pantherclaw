// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// ParamType is the declared type of a parameter (F378).
type ParamType string

// Parameter types. Text is untrusted agent prose: never material, never
// shown in approval fields, never visible to policy (HR-023). Command is
// the exact text of a command a cooperative client is about to run (G0 M6,
// pc.shell): it may be material, policies see it as sent, and control
// characters other than tab and newline, and format and bidi characters,
// are refused (HR-102). Path is an absolute file-system path in its one
// normalized spelling (actionir.NormalizePath, HR-187). Content is text the
// target stores or shows exactly as written, such as a pull request's title
// (G0 M8): unlike text it is sent from a dispatch template, so it is always
// material (bound by the permit and any approval, and visible to policy),
// and it is refused like a command when it holds control, format or bidi
// characters.
const (
	TypeMoney          ParamType = "money"
	TypeDecimal        ParamType = "decimal"
	TypeInteger        ParamType = "integer"
	TypeEnum           ParamType = "enum"
	TypeIdentifier     ParamType = "identifier"
	TypeIdentifierList ParamType = "identifier_list"
	TypeBoolean        ParamType = "boolean"
	TypeText           ParamType = "text"
	TypeCommand        ParamType = "command"
	TypeContent        ParamType = "content"
	TypePath           ParamType = "path"
)

// Unit is the unit of a decimal or integer parameter. The list is closed:
// anything else is unsupported (HR-103).
type Unit string

// Units.
var Units = []Unit{"count", "items", "rows", "records", "recipients", "bytes", "seconds", "percent"}

// ParamSpec declares one parameter.
type ParamSpec struct {
	Type       ParamType `json:"type"`
	Material   bool      `json:"material,omitzero"`
	Required   bool      `json:"required,omitzero"`
	Unit       Unit      `json:"unit,omitzero"`
	Currencies []string  `json:"currencies,omitzero"`
	Min        string    `json:"min,omitzero"`
	Max        string    `json:"max,omitzero"`
	Values     []string  `json:"values,omitzero"`
	Pattern    string    `json:"pattern,omitzero"`
	MaxLength  int       `json:"max_length,omitzero"`
	MaxItems   int       `json:"max_items,omitzero"`
	// Disclosure marks a parameter that can carry data out (HR-079, G0 M10
	// D56): toward a public destination its value is limited to MaxBytes
	// (0: DefaultDisclosureBytes) and MaxEntropy bits per byte (0:
	// DefaultDisclosureEntropy), which the gateway checks before dispatch.
	Disclosure bool   `json:"disclosure,omitzero"`
	MaxBytes   int    `json:"max_bytes,omitzero"`
	MaxEntropy string `json:"max_entropy,omitzero"` // decimal, e.g. "6.0"
}

const (
	maxParamText = 8 << 10 // PAP-1 §6 material string limit
	maxListItems = 256
)

func (p ParamSpec) validate(name string) error {
	numeric := p.Type == TypeMoney || p.Type == TypeDecimal || p.Type == TypeInteger
	switch {
	case p.Type == TypeText && p.Material:
		return invalid("%s: text is untrusted and can never be material (HR-023)", name)
	case p.Type == TypeContent && !p.Material:
		return invalid("%s: content is sent to the target, so it must be material", name)
	case (p.Unit != "") != (p.Type == TypeDecimal || p.Type == TypeInteger):
		return invalid("%s: decimal and integer params need a unit; other types take none", name)
	case p.Unit != "" && !slices.Contains(Units, p.Unit):
		return invalid("%s: unsupported unit %q", name, p.Unit)
	case (len(p.Currencies) > 0) != (p.Type == TypeMoney):
		return invalid("%s: money params list their currencies; other types take none", name)
	case (p.Min != "" || p.Max != "") && !numeric:
		return invalid("%s: min/max apply to numeric params only", name)
	case (len(p.Values) > 0) != (p.Type == TypeEnum):
		return invalid("%s: enum params list their values; other types take none", name)
	case p.Pattern != "" && p.Type != TypeIdentifier && p.Type != TypeIdentifierList:
		return invalid("%s: pattern applies to identifiers only", name)
	case p.MaxLength < 0 || p.MaxLength > maxParamText:
		return invalid("%s: max_length must be 0..%d", name, maxParamText)
	case !p.Disclosure && (p.MaxBytes != 0 || p.MaxEntropy != ""):
		return invalid("%s: max_bytes and max_entropy apply to disclosure params only", name)
	case p.Disclosure && !slices.Contains(disclosureTypes, p.Type):
		return invalid("%s: only text, content, command, path and identifier params can be disclosure params", name)
	case p.MaxBytes < 0 || p.MaxBytes > maxParamText:
		return invalid("%s: max_bytes must be 0..%d", name, maxParamText)
	case p.MaxEntropy != "" && !validEntropy(p.MaxEntropy):
		return invalid("%s: max_entropy must be a decimal above 0 and at most 8 bits per byte", name)
	case (p.MaxItems != 0) != (p.Type == TypeIdentifierList) || p.MaxItems < 0 || p.MaxItems > maxListItems:
		return invalid("%s: identifier_list params need max_items 1..%d; other types take none", name, maxListItems)
	}
	switch p.Type {
	case TypeMoney:
		for _, c := range p.Currencies {
			if _, err := money.ParseCurrency(c); err != nil {
				return invalid("%s: %v", name, err)
			}
		}
	case TypeEnum:
		for _, v := range p.Values {
			if err := actionir.CheckIdentifier(name, v); err != nil {
				return invalid("%s: enum value %q", name, v)
			}
		}
	case TypeIdentifier, TypeIdentifierList:
		if p.Pattern != "" {
			return anchored(name+": pattern", p.Pattern)
		}
	case TypePath:
		if p.MaxLength > actionir.MaxPath {
			return invalid("%s: max_length of a path is at most %d", name, actionir.MaxPath)
		}
	case TypeDecimal, TypeInteger, TypeBoolean, TypeText, TypeCommand, TypeContent:
	default:
		return invalid("%s: unknown type %q", name, p.Type)
	}
	for _, b := range []string{p.Min, p.Max} {
		if _, err := p.parseNumber(b); b != "" && err != nil {
			return invalid("%s: bound %q: %v", name, b, err)
		}
	}
	return nil
}

var integerRe = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,17})$`)

func (p ParamSpec) parseNumber(s string) (money.Decimal, error) {
	if p.Type == TypeInteger && !integerRe.MatchString(s) {
		return money.Decimal{}, fmt.Errorf("%q is not an integer", s)
	}
	return money.Parse(s)
}

// checkText rejects bidi and other control characters (HR-102); tabs and
// newlines are allowed in prose.
func checkText(name, s string) error {
	for _, r := range s {
		if r == '\t' || r == '\n' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar ||
			unicode.Is(unicode.Cf, r) {
			return invalid("%s contains a control, format or bidi character (HR-102)", name)
		}
	}
	return nil
}

// Disclosure defaults (HR-079, G0 M10 D56).
const (
	DefaultDisclosureBytes   = 4096
	DefaultDisclosureEntropy = 6.0
)

// disclosureTypes are the parameter types a disclosure param may have:
// the ones that carry free bytes to the target.
var disclosureTypes = []ParamType{TypeText, TypeContent, TypeCommand, TypePath, TypeIdentifier, TypeIdentifierList}

// DisclosureLimits returns a disclosure param's byte and entropy limits,
// with the defaults filled in.
func (p ParamSpec) DisclosureLimits() (maxBytes int, maxEntropy float64) {
	maxBytes, maxEntropy = p.MaxBytes, 0
	if p.MaxEntropy != "" {
		maxEntropy, _ = strconv.ParseFloat(p.MaxEntropy, 64) // validated
	}
	if maxBytes == 0 {
		maxBytes = DefaultDisclosureBytes
	}
	if maxEntropy == 0 {
		maxEntropy = DefaultDisclosureEntropy
	}
	return maxBytes, maxEntropy
}

// Disclosed is the bytes a value discloses: its text, or a list's items
// joined by newlines.
func (v Value) Disclosed() []byte {
	if v.Type == TypeIdentifierList {
		return []byte(strings.Join(v.List, "\n"))
	}
	return []byte(v.Str)
}

// Entropy is the Shannon entropy of b in bits per byte (0 for no bytes).
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n, h := float64(len(b)), 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var entropyRe = regexp.MustCompile(`^[0-9](\.[0-9]{1,3})?$`)

// validEntropy reports a decimal entropy limit above 0 and at most 8.
func validEntropy(s string) bool {
	if !entropyRe.MatchString(s) {
		return false
	}
	v, err := strconv.ParseFloat(s, 64)
	return err == nil && v > 0 && v <= 8
}
