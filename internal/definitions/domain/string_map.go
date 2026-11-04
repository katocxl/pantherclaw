// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

// TypeStringMap is a flat map of string keys to string values, such as a
// record's metadata or an equality filter (G0 M30 D922b): at most MaxKeys
// keys. Like a float_array, the gateway binds it as a query parameter and
// never sends it from a template; policies cannot see it. Content signals
// scan its values as they scan any param.
const TypeStringMap ParamType = "string_map"

// String map limits (D922b).
const (
	MaxStringMapKeys  = 32
	MaxStringMapValue = 1 << 10
	MaxStringMapBytes = 8 << 10
)

// StringMapKeyRe is a string map key.
var StringMapKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// decodeStringMap strictly decodes a string_map: a JSON object of string
// values (duplicate members are refused), within its limits.
func (p ParamSpec) decodeStringMap(raw jsontext.Value) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("must be an object of string values")
	}
	return m, p.stringMap(m)
}

func (p ParamSpec) stringMap(m map[string]string) error {
	if len(m) > p.MaxKeys {
		return fmt.Errorf("at most %d keys", p.MaxKeys)
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		if !StringMapKeyRe.MatchString(k) {
			return fmt.Errorf("key %q is not a name", k)
		}
		if len(m[k]) > MaxStringMapValue {
			return fmt.Errorf("value of %s is longer than %d bytes", k, MaxStringMapValue)
		}
		if err := checkText("value of "+k, m[k]); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(m, json.Deterministic(true))
	if err != nil || len(raw) > MaxStringMapBytes {
		return fmt.Errorf("at most %d bytes in all", MaxStringMapBytes)
	}
	return nil
}
