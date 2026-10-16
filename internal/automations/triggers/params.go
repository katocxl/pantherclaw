// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/jsonptr"
)

// Trigger data reaches a definition only as declared, typed, bounded
// parameters (HR-276): each declared parameter is read from its `from`,
// converted to its type within its bounds, and nothing else is read.
// Any failure refuses the trigger (REFUSED_INVALID).

// ErrParams wraps every extraction failure.
var ErrParams = errors.New("triggers: trigger parameters")

func paramsErr(name, why string) error { return fmt.Errorf("%w: %s: %s", ErrParams, name, why) }

// ExtractInbound reads declared parameters from an inbound JSON body with
// their RFC 6901 pointers. A pointer naming an object, an array or null is
// refused: only scalars become parameters.
func ExtractInbound(specs map[string]autodomain.ParamSpec, body []byte) (map[string]autodomain.Value, error) {
	out := map[string]autodomain.Value{}
	for _, name := range slices.Sorted(maps.Keys(specs)) {
		spec := specs[name]
		ptr, err := jsonptr.Parse(spec.From)
		if err != nil || spec.From == "" {
			return nil, paramsErr(name, "its source is not a JSON Pointer")
		}
		raw, err := ptr.Lookup(body)
		switch {
		case errors.Is(err, jsonptr.ErrNotFound):
			if spec.IsRequired() {
				return nil, paramsErr(name, "missing")
			}
			continue
		case err != nil:
			return nil, paramsErr(name, "the body is not valid JSON")
		}
		switch raw.Kind() { //nolint:exhaustive // scalars, null, or anything else
		case '"', '0', 't', 'f':
		case 'n':
			if spec.IsRequired() {
				return nil, paramsErr(name, "missing")
			}
			continue
		default:
			return nil, paramsErr(name, "only a string, number or boolean can be a parameter")
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, paramsErr(name, "unreadable")
		}
		val, err := spec.Convert(name, v)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrParams, err)
		}
		out[name] = val
	}
	return out, nil
}

// ExtractFields reads declared parameters through get (event fields, probe
// subject fields): values are text, converted to the declared type.
func ExtractFields(specs map[string]autodomain.ParamSpec, get func(path string) (string, bool)) (map[string]autodomain.Value, error) {
	out := map[string]autodomain.Value{}
	for _, name := range slices.Sorted(maps.Keys(specs)) {
		spec := specs[name]
		raw, ok := get(spec.From)
		if !ok || spec.From == "" {
			if spec.IsRequired() {
				return nil, paramsErr(name, "missing")
			}
			continue
		}
		val, err := spec.Convert(name, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrParams, err)
		}
		out[name] = val
	}
	return out, nil
}

// ExtractManual reads a person's form values: every given name must be
// declared, and every required parameter given.
func ExtractManual(specs map[string]autodomain.ParamSpec, given map[string]string) (map[string]autodomain.Value, error) {
	for name := range given {
		if _, ok := specs[name]; !ok {
			return nil, paramsErr(name, "not a declared parameter")
		}
	}
	return ExtractFields(specs, func(path string) (string, bool) {
		v, ok := given[path]
		return v, ok
	})
}

// manualSpecs keys manual parameters by name: a form field is its
// parameter's name, whatever `from` says.
func manualSpecs(specs map[string]autodomain.ParamSpec) map[string]autodomain.ParamSpec {
	out := make(map[string]autodomain.ParamSpec, len(specs))
	for name, s := range specs {
		s.From = name
		out[name] = s
	}
	return out
}
