// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

// ErrTemplate reports a `with` that cannot be rendered (HR-276).
var ErrTemplate = errors.New("engine: template")

// placeholder is {{params.<name>}} or {{steps.<id>.output.<key>}}.
var placeholder = regexp.MustCompile(`\{\{\s*(?:params\.([a-z_][a-z0-9_]{0,63})|steps\.([a-z][a-z0-9_-]{0,62})\.output\.([A-Za-z0-9_]{1,64}))\s*\}\}`)

// render fills the templatable fields of spec's `with` from the trigger's
// typed parameters and earlier steps' outputs, then decodes it into the
// kind's schema (HR-276). Rendering is typed: a field that holds an
// identifier (a pointer through "ids") takes exactly one placeholder and
// nothing else, so no identifier is ever concatenated; text fields may mix
// text and placeholders. A placeholder outside a templatable field, or
// naming a parameter or output that does not exist, is an error. The
// rendered value's own bounds (for example a narrowing inside the
// ceiling) are the step runtime's to check.
func render(spec autodomain.StepSpec, params map[string]autodomain.Value, outputs map[string]map[string]string) (any, error) {
	kind, ok := autodomain.Catalog[spec.Step]
	if !ok {
		return nil, fmt.Errorf("%w: unknown kind %q", ErrTemplate, spec.Step)
	}
	if len(spec.With) == 0 {
		return kind.DecodeWith(nil)
	}
	var doc any
	if err := json.Unmarshal(spec.With, &doc); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplate, err)
	}
	r := renderer{patterns: kind.Templatable, params: params, outputs: outputs}
	doc, err := r.walk("", doc)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(doc, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplate, err)
	}
	return kind.DecodeWith(raw)
}

type renderer struct {
	patterns []string
	params   map[string]autodomain.Value
	outputs  map[string]map[string]string
}

func (r renderer) walk(ptr string, v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			out, err := r.walk(ptr+"/"+escapePointer(k), e)
			if err != nil {
				return nil, err
			}
			t[k] = out
		}
		return t, nil
	case []any:
		for i, e := range t {
			out, err := r.walk(ptr+"/"+strconv.Itoa(i), e)
			if err != nil {
				return nil, err
			}
			t[i] = out
		}
		return t, nil
	case string:
		if !strings.Contains(t, "{{") {
			return t, nil
		}
		pattern, ok := r.match(ptr)
		if !ok {
			return nil, fmt.Errorf("%w: %s is not templatable", ErrTemplate, ptr)
		}
		return r.fill(ptr, t, strings.Contains(pattern, "/ids/"))
	}
	return v, nil
}

// match returns the templatable pattern ptr matches.
func (r renderer) match(ptr string) (string, bool) {
	segs := strings.Split(ptr, "/")
	for _, p := range r.patterns {
		ps := strings.Split(p, "/")
		if len(ps) != len(segs) {
			continue
		}
		ok := true
		for i := range ps {
			if ps[i] != "*" && ps[i] != segs[i] {
				ok = false
				break
			}
		}
		if ok {
			return p, true
		}
	}
	return "", false
}

// fill replaces every placeholder of s; an identifier field must be one
// placeholder exactly.
func (r renderer) fill(ptr, s string, identifier bool) (string, error) {
	if identifier {
		loc := placeholder.FindStringIndex(s)
		if loc == nil || loc[0] != 0 || loc[1] != len(s) {
			return "", fmt.Errorf("%w: %s takes exactly one placeholder", ErrTemplate, ptr)
		}
	}
	if strings.Contains(placeholder.ReplaceAllString(s, ""), "{{") {
		// A malformed placeholder is refused rather than passed on.
		return "", fmt.Errorf("%w: %s: malformed placeholder", ErrTemplate, ptr)
	}
	var err error
	out := placeholder.ReplaceAllStringFunc(s, func(m string) string {
		sub := placeholder.FindStringSubmatch(m)
		if sub[1] != "" {
			v, ok := r.params[sub[1]]
			if !ok {
				err = fmt.Errorf("%w: %s: no parameter %q", ErrTemplate, ptr, sub[1])
				return ""
			}
			return v.Text()
		}
		v, ok := r.outputs[sub[2]][sub[3]]
		if !ok {
			err = fmt.Errorf("%w: %s: step %q has no output %q", ErrTemplate, ptr, sub[2], sub[3])
			return ""
		}
		return v
	})
	if err != nil {
		return "", err
	}
	if identifier && out == "" {
		return "", fmt.Errorf("%w: %s: empty identifier", ErrTemplate, ptr)
	}
	return out, nil
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
