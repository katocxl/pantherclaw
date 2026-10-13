// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"regexp"
	"slices"
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
