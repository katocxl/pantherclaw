// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ports

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"slices"
)

// Schema is a node of an output's JSON schema.
type Schema map[string]any

// Object is a closed object: every property is required and no other is
// allowed, so an extra field cannot be asked for (HR-543).
func Object(props map[string]Schema) Schema {
	return Schema{
		"type": "object", "additionalProperties": false, "properties": props,
		"required": slices.Sorted(maps.Keys(props)),
	}
}

// Array is a list of items.
func Array(items Schema) Schema { return Schema{"type": "array", "items": items} }

// Text is a string, described for the model.
func Text(description string) Schema { return Schema{"type": "string", "description": description} }

// Integer is a whole number, described for the model.
func Integer(description string) Schema { return Schema{"type": "integer", "description": description} }

// Enum is one of values.
func Enum(values []string) Schema { return Schema{"type": "string", "enum": values} }

// Nullable is s or null.
func Nullable(s Schema) Schema { return Schema{"anyOf": []Schema{s, {"type": "null"}}} }

// Encode returns the schema's JSON.
func (s Schema) Encode() (jsontext.Value, error) {
	return json.Marshal(s, json.Deterministic(true))
}
