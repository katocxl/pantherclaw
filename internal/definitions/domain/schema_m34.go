// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
)

// The two gateway-bound input schema forms (G0 M34 D1002a): a number array,
// the schema of a float_array param, and a string map, the schema of a
// string_map param. Each is allowed only on a root property whose mapped
// param has that type, so no other tool argument can take either form.

// maxSchemaMapKeys bounds a string map's maxProperties, and
// maxSchemaMapValue its values' maxLength.
const (
	maxSchemaMapKeys  = 32
	maxSchemaMapValue = 1024
)

// stringMap reports whether s uses a string map's keywords.
func (s *Schema) stringMap() bool {
	return s.PropertyNames != nil || s.MaxProperties != 0 || s.AdditionalSchema != nil
}

// equalShape reports whether s carries no keyword beyond o's type.
func (s *Schema) equalShape(o *Schema) bool {
	return s.Type == o.Type && len(s.Properties) == 0 && len(s.Required) == 0 && s.AdditionalProperties == nil &&
		s.AdditionalSchema == nil && s.PropertyNames == nil && s.MaxProperties == 0 && len(s.Enum) == 0 &&
		s.Pattern == "" && s.MinLength == 0 && s.MaxLength == 0 && s.Minimum == nil && s.Maximum == nil &&
		s.Items == nil && s.MaxItems == 0 && s.Header == ""
}

// validateNumberArray checks a number array: items exactly {type: number},
// maxItems 1..MaxFloatItems, nothing else, on a float_array's property.
func (s *Schema) validateNumberArray(at string, c *schemaCheck) error {
	if c.forms[at] != TypeFloatArray {
		return invalid("%s: a number array is the schema of a float_array param's property only", at)
	}
	c.nodes++
	items := *s.Items
	items.Description = ""
	rest := *s
	rest.Items, rest.MaxItems, rest.Type, rest.Description = nil, 0, "", ""
	switch {
	case !items.equalShape(&Schema{Type: "number"}) || !rest.equalShape(&Schema{}):
		return invalid("%s: a number array takes items {type: number} and maxItems only", at)
	case s.MaxItems < 1 || s.MaxItems > MaxFloatItems:
		return invalid("%s: a number array takes maxItems 1..%d", at, MaxFloatItems)
	}
	if s.Items.Description != "" {
		if err := text(at+".items.description", s.Items.Description); err != nil {
			return err
		}
	}
	return nil
}

// validateStringMap checks a string map: propertyNames with an anchored
// pattern, maxProperties 1..32, additionalProperties a string with maxLength
// 1..1024, and no properties or required, on a string_map's property.
func (s *Schema) validateStringMap(at string, c *schemaCheck) error {
	if c.forms[at] != TypeStringMap {
		return invalid("%s: a string map is the schema of a string_map param's property only", at)
	}
	c.nodes += 2
	rest := *s
	rest.Type, rest.Description, rest.PropertyNames, rest.MaxProperties, rest.AdditionalSchema = "", "", nil, 0, nil
	names, values := s.PropertyNames, s.AdditionalSchema
	switch {
	case !rest.equalShape(&Schema{}):
		return invalid("%s: a string map takes propertyNames, maxProperties and additionalProperties only", at)
	case s.MaxProperties < 1 || s.MaxProperties > maxSchemaMapKeys:
		return invalid("%s: a string map takes maxProperties 1..%d", at, maxSchemaMapKeys)
	case names == nil || (names.Type != "" && names.Type != "string") || names.Pattern == "":
		return invalid("%s.propertyNames: a pattern", at)
	case values == nil || values.Type != "string" || values.MaxLength < 1 || values.MaxLength > maxSchemaMapValue:
		return invalid("%s.additionalProperties: a string with maxLength 1..%d", at, maxSchemaMapValue)
	}
	n := *names
	n.Type, n.Pattern = "", ""
	v := *values
	v.MaxLength, v.Description = 0, ""
	if !n.equalShape(&Schema{}) || !v.equalShape(&Schema{Type: "string"}) {
		return invalid("%s: a string map's propertyNames is a pattern and its values a string with maxLength", at)
	}
	return anchored(at+".propertyNames.pattern", names.Pattern)
}

// schemaForms are the root properties of m's input schema, by path, whose
// mapped param is a float_array or a string_map: extract maps the param
// from exactly input.<property> or input.?<property>.
func (d *Definition) schemaForms(at string, m Mapping) map[string]ParamType {
	forms := map[string]ParamType{}
	for name, expr := range m.Extract.Params {
		t := d.Params[name].Type
		if t != TypeFloatArray && t != TypeStringMap {
			continue
		}
		prop, ok := strings.CutPrefix(expr, "input.?")
		if !ok {
			prop, ok = strings.CutPrefix(expr, "input.")
		}
		if ok && fieldRe.MatchString(prop) {
			forms[at+".properties."+prop] = t
		}
	}
	return forms
}

// schemaJSON is Schema's wire form: additionalProperties is a boolean or,
// on a string map, a schema.
type schemaJSON struct {
	schemaFields         `json:",inline"`
	AdditionalProperties jsontext.Value `json:"additionalProperties,omitzero"`
}

// schemaFields is Schema without its JSON methods.
type schemaFields Schema

// UnmarshalJSON decodes a schema strictly: unknown keywords are refused.
func (s *Schema) UnmarshalJSON(b []byte) error {
	var aux schemaJSON
	if err := json.Unmarshal(b, &aux, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	*s = Schema(aux.schemaFields)
	switch raw := strings.TrimSpace(string(aux.AdditionalProperties)); {
	case raw == "":
	case raw == "true" || raw == "false":
		v := raw == "true"
		s.AdditionalProperties = &v
	default:
		var sub Schema
		if err := json.Unmarshal(aux.AdditionalProperties, &sub); err != nil {
			return err
		}
		s.AdditionalSchema = &sub
	}
	return nil
}

// MarshalJSON encodes a schema as MCP clients receive it.
func (s Schema) MarshalJSON() ([]byte, error) {
	aux := schemaJSON{schemaFields: schemaFields(s)}
	var err error
	switch {
	case s.AdditionalProperties != nil:
		aux.AdditionalProperties, err = json.Marshal(*s.AdditionalProperties)
	case s.AdditionalSchema != nil:
		aux.AdditionalProperties, err = json.Marshal(s.AdditionalSchema, json.Deterministic(true))
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(aux, json.Deterministic(true))
}
