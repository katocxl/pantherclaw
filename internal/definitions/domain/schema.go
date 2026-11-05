// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"
	"strings"
)

// Schema is the reviewed input schema of an MCP tool: what MCP clients
// receive in tools/list (HR-081). It is a small JSON Schema subset: objects
// with closed properties, strings with patterns or enums, integers,
// booleans and arrays. There is no $ref, no composition and no format;
// every other keyword is refused when the package is decoded. Two narrow
// forms serve gateway-bound params (G0 M34 D1002a): a number array for a
// float_array and a string map for a string_map.
type Schema struct {
	Type        string `json:"type,omitzero"` // empty only on propertyNames (G0 M34 D1002a)
	Description string `json:"description,omitzero"`
	// Objects. additionalProperties is false, or, on a string map, a string
	// schema (AdditionalSchema); see MarshalJSON and UnmarshalJSON.
	Properties           map[string]*Schema `json:"properties,omitzero"`
	Required             []string           `json:"required,omitzero"`
	AdditionalProperties *bool              `json:"-"`
	AdditionalSchema     *Schema            `json:"-"`
	// String maps (G0 M34 D1002a).
	PropertyNames *Schema `json:"propertyNames,omitzero"`
	MaxProperties int     `json:"maxProperties,omitzero"`
	// Strings.
	Enum      []string `json:"enum,omitzero"`
	Pattern   string   `json:"pattern,omitzero"`
	MinLength int      `json:"minLength,omitzero"`
	MaxLength int      `json:"maxLength,omitzero"`
	// Integers.
	Minimum *int64 `json:"minimum,omitzero"`
	Maximum *int64 `json:"maximum,omitzero"`
	// Arrays.
	Items    *Schema `json:"items,omitzero"`
	MaxItems int     `json:"maxItems,omitzero"`
	// Header, on a string, integer or boolean property reached from the
	// root through properties only, names the Mcp-Param-{Header} HTTP
	// header MCP clients mirror the argument into (MCP 2026-07-28,
	// x-mcp-header); the MCP face checks it against the body (HR-080).
	// Names are unique in an input schema, ignoring case.
	Header string `json:"x-mcp-header,omitzero"`
}

const (
	maxSchemaDepth = 4
	maxSchemaNodes = 256
	maxEnum        = 64
	// maxHeaders bounds a tool's x-mcp-header declarations.
	maxHeaders = 32
)

// schemaCheck is the state of one input schema's validation.
type schemaCheck struct {
	nodes int
	// forms are the root properties whose mapped param is a float_array or
	// a string_map, by their path: only they may take the number-array or
	// string-map form (G0 M34 D1002a).
	forms map[string]ParamType
	// headers are the x-mcp-header names declared so far, in lower case.
	headers map[string]bool
}

// validateSchema checks an input schema: the root is an object. forms
// names the root properties, by path, that may take a gateway-bound form.
func validateSchema(at string, s *Schema, forms map[string]ParamType) error {
	if s == nil || s.Type != "object" {
		return invalid("%s: the root of an input schema is an object", at)
	}
	return s.validate(at, 0, true, &schemaCheck{headers: map[string]bool{}, forms: forms})
}

// validate checks one node; reachable says it is reached from the root
// through properties only.
func (s *Schema) validate(at string, depth int, reachable bool, c *schemaCheck) error {
	c.nodes++
	switch {
	case c.nodes > maxSchemaNodes:
		return invalid("%s: more than %d schema nodes", at, maxSchemaNodes)
	case depth > maxSchemaDepth:
		return invalid("%s: deeper than %d levels", at, maxSchemaDepth)
	}
	if s.Header != "" {
		if err := s.validateHeader(at, depth, reachable, c); err != nil {
			return err
		}
	}
	if s.Description != "" {
		if err := text(at+".description", s.Description); err != nil {
			return err
		}
	}
	if s.Type == "array" && s.Items != nil && s.Items.Type == "number" {
		return s.validateNumberArray(at, c)
	}
	if s.Type == "object" && s.stringMap() {
		return s.validateStringMap(at, c)
	}
	if s.stringMap() {
		return invalid("%s: propertyNames, maxProperties and an additionalProperties schema belong to a string map", at)
	}
	object := len(s.Properties) > 0 || len(s.Required) > 0 || s.AdditionalProperties != nil
	str := len(s.Enum) > 0 || s.Pattern != "" || s.MinLength != 0 || s.MaxLength != 0
	integer := s.Minimum != nil || s.Maximum != nil
	array := s.Items != nil || s.MaxItems != 0
	switch s.Type {
	case "object":
		if str || integer || array {
			return invalid("%s: an object takes properties, required and additionalProperties only", at)
		}
		return s.validateObject(at, depth, reachable, c)
	case "string":
		if object || integer || array {
			return invalid("%s: a string takes enum, pattern, minLength and maxLength only", at)
		}
		return s.validateString(at)
	case "integer":
		if object || str || array {
			return invalid("%s: an integer takes minimum and maximum only", at)
		}
		if s.Minimum != nil && s.Maximum != nil && *s.Minimum > *s.Maximum {
			return invalid("%s: minimum above maximum", at)
		}
		return nil
	case "boolean":
		if object || str || integer || array {
			return invalid("%s: a boolean takes no keywords", at)
		}
		return nil
	case "array":
		if object || str || integer || s.Items == nil || s.MaxItems < 1 || s.MaxItems > maxListItems {
			return invalid("%s: an array takes items and maxItems 1..%d", at, maxListItems)
		}
		return s.Items.validate(at+".items", depth+1, false, c)
	default:
		return invalid("%s: type must be object, string, integer, boolean or array", at)
	}
}

func (s *Schema) validateObject(at string, depth int, reachable bool, c *schemaCheck) error {
	if s.AdditionalProperties == nil || *s.AdditionalProperties {
		return invalid("%s: an object must set additionalProperties: false", at)
	}
	if len(s.Properties) > maxItems {
		return invalid("%s: at most %d properties", at, maxItems)
	}
	for _, name := range slices.Sorted(maps.Keys(s.Properties)) {
		if !fieldRe.MatchString(name) || s.Properties[name] == nil {
			return invalid("%s: property %q", at, name)
		}
		if err := s.Properties[name].validate(at+".properties."+name, depth+1, reachable, c); err != nil {
			return err
		}
	}
	for i, r := range s.Required {
		if s.Properties[r] == nil || slices.Contains(s.Required[:i], r) {
			return invalid("%s: required %q is not a property or appears twice", at, r)
		}
	}
	return nil
}

func (s *Schema) validateString(at string) error {
	switch {
	case s.MinLength < 0 || s.MaxLength < 0 || s.MaxLength > maxParamText || (s.MaxLength > 0 && s.MinLength > s.MaxLength):
		return invalid("%s: minLength and maxLength within 0..%d, minLength not above maxLength", at, maxParamText)
	case len(s.Enum) > maxEnum:
		return invalid("%s: at most %d enum values", at, maxEnum)
	}
	for i, v := range s.Enum {
		if v == "" || len(v) > 256 || slices.Contains(s.Enum[:i], v) {
			return invalid("%s: enum value %q is empty, too long or repeated", at, v)
		}
		if err := checkText(at+".enum", v); err != nil {
			return err
		}
	}
	if s.Pattern != "" {
		return anchored(at+".pattern", s.Pattern)
	}
	return nil
}

// validateHeader checks an x-mcp-header declaration: on a string, integer
// or boolean property reached through properties only (never the root or
// inside items), a header name, unique ignoring case.
func (s *Schema) validateHeader(at string, depth int, reachable bool, c *schemaCheck) error {
	key := strings.ToLower(s.Header)
	switch {
	case !reachable || depth == 0:
		return invalid("%s: x-mcp-header only on a property reached from the root through properties", at)
	case s.Type != "string" && s.Type != "integer" && s.Type != "boolean":
		return invalid("%s: x-mcp-header only on a string, integer or boolean", at)
	case !headerRe.MatchString(s.Header):
		return invalid("%s: x-mcp-header %q is not a header name (a letter, then letters, digits and hyphens, at most 64)", at, s.Header)
	case c.headers[key]:
		return invalid("%s: x-mcp-header %q is declared twice, ignoring case", at, s.Header)
	case len(c.headers) >= maxHeaders:
		return invalid("%s: more than %d x-mcp-header declarations", at, maxHeaders)
	}
	c.headers[key] = true
	return nil
}
