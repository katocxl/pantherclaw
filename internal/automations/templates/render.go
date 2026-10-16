// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package templates

import (
	"bytes"
	"fmt"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

// A template's definition and tests are YAML with three directives,
// applied to the parsed node tree:
//
//	"${name}"                    a scalar that is exactly a placeholder is
//	                             replaced by the parameter's value: one
//	                             typed scalar, or a sequence for a list
//	{$when: {param: p, set: b}}  a mapping holding $when is kept only when
//	{$when: {param: p, in: [..]}}  the condition holds (else its entry or
//	                             item is dropped); with $value it is
//	                             replaced by $value
//	{$switch: p, $cases: {..}}   replaced by the case of p's value
//
// Keys are never substituted, and a value never becomes YAML text, so a
// value cannot add structure or templates.

// values are the resolved parameters: canonical items by name (absent when
// unset).
type values struct {
	params map[string]Param
	set    map[string][]string
	// missing collects optional parameters a chosen option needs.
	missing map[string]bool
}

// resolve checks the given parameters against the declarations: unknown
// names, missing required values, invalid values and unmet requirements
// are all reported together.
func (e *entry) resolve(given map[string]string) (*values, error) {
	v := &values{params: map[string]Param{}, set: map[string][]string{}, missing: map[string]bool{}}
	var problems []string
	for name := range given {
		if _, ok := e.param(name); !ok {
			problems = append(problems, fmt.Sprintf("%s: unknown parameter", name))
		}
	}
	for _, p := range e.t.Params {
		v.params[p.Name] = p
		raw, ok := given[p.Name]
		if !ok || raw == "" {
			raw = p.Default
		}
		if raw == "" {
			if p.IsRequired() {
				problems = append(problems, fmt.Sprintf("%s: missing", p.Name))
			}
			continue
		}
		items, err := convert(p, raw)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", p.Name, err))
			continue
		}
		v.set[p.Name] = items
	}
	for _, p := range e.t.Params {
		if _, ok := v.set[p.Name]; !ok {
			continue
		}
		for _, r := range p.Requires {
			if _, ok := v.set[r]; !ok {
				problems = append(problems, fmt.Sprintf("%s: needed with %s", r, p.Name))
			}
		}
	}
	if len(problems) > 0 {
		return nil, paramsErr(problems)
	}
	return v, nil
}

func paramsErr(problems []string) error {
	sort.Strings(problems)
	return fmt.Errorf("%w: %s", ErrParams, strings.Join(slices.Compact(problems), "; "))
}

// text is a single-valued parameter's value.
func (v *values) text(name string) (string, bool) {
	items, ok := v.set[name]
	if !ok || len(items) != 1 || v.params[name].List {
		return "", false
	}
	return items[0], true
}

// render returns a fresh copy of n with the directives applied, or keep
// false when n is dropped. Comments are not copied.
func (v *values) render(n *yaml.Node) (*yaml.Node, bool, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		if m := placeholder.FindStringSubmatch(n.Value); m != nil && n.Tag == "!!str" {
			return v.substitute(m[1]), true, nil
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: n.Tag, Value: n.Value, Style: n.Style &^ yaml.TaggedStyle}, true, nil
	case yaml.SequenceNode:
		out := &yaml.Node{Kind: yaml.SequenceNode, Tag: n.Tag}
		for _, c := range n.Content {
			r, keep, err := v.render(c)
			if err != nil {
				return nil, false, err
			}
			if keep {
				out.Content = append(out.Content, r)
			}
		}
		return out, true, nil
	case yaml.MappingNode:
	case yaml.DocumentNode, yaml.AliasNode:
		return nil, false, fmt.Errorf("line %d: unexpected YAML node", n.Line)
	}
	if p, ok := lookup(n, dirSwitch); ok {
		val, ok := v.text(p.Value)
		if !ok {
			v.missing[p.Value] = true
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str"}, true, nil
		}
		cases, _ := lookup(n, dirCases)
		c, ok := lookup(cases, val)
		if !ok {
			return nil, false, fmt.Errorf("line %d: no case for %s=%q", n.Line, p.Value, val)
		}
		return v.render(c)
	}
	if c, ok := lookup(n, dirWhen); ok {
		cond, err := decodeCond(c)
		if err != nil {
			return nil, false, err
		}
		if !v.holds(cond) {
			return nil, false, nil
		}
		if val, ok := lookup(n, dirValue); ok {
			return v.render(val)
		}
	}
	out := &yaml.Node{Kind: yaml.MappingNode, Tag: n.Tag}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if k.Value == dirWhen {
			continue
		}
		r, keep, err := v.render(n.Content[i+1])
		if err != nil {
			return nil, false, err
		}
		if keep {
			out.Content = append(out.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: k.Tag, Value: k.Value}, r)
		}
	}
	return out, true, nil
}

func (v *values) holds(c cond) bool {
	items, set := v.set[c.Param]
	if c.Set != nil {
		return set == *c.Set
	}
	return set && len(items) == 1 && slices.Contains(c.In, items[0])
}

// substitute returns the parameter's value as typed nodes. Strings are
// double-quoted scalars: whatever they hold stays one string.
func (v *values) substitute(name string) *yaml.Node {
	p := v.params[name]
	items, ok := v.set[name]
	if !ok {
		v.missing[name] = true
		items = []string{""}
	}
	scalar := func(s string) *yaml.Node {
		switch p.Type {
		case autodomain.ParamInt:
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: s}
		case autodomain.ParamBool:
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: s}
		case autodomain.ParamString, autodomain.ParamEnum, autodomain.ParamUUID, autodomain.ParamDecimal:
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s, Style: yaml.DoubleQuotedStyle}
	}
	if !p.List {
		return scalar(items[0])
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, it := range items {
		seq.Content = append(seq.Content, scalar(it))
	}
	return seq
}

// Render renders template id with params into a definition document
// (YAML, without name and owner; autodomain.Parse accepts it) and the
// template's baseline tests for that document. Unknown, missing or invalid
// parameters are an ErrParams error listing each one.
func Render(id string, params map[string]string) ([]byte, []TestCase, error) {
	e, ok := library[id]
	if !ok {
		return nil, nil, fmt.Errorf("%w %q", ErrUnknown, id)
	}
	v, err := e.resolve(params)
	if err != nil {
		return nil, nil, err
	}
	defNode, _, err := v.render(e.def)
	if err != nil {
		return nil, nil, err
	}
	testsNode, _, err := v.render(e.tests)
	if err != nil {
		return nil, nil, err
	}
	if len(v.missing) > 0 {
		var problems []string
		for name := range v.missing {
			problems = append(problems, name+": missing (the chosen options need it)")
		}
		return nil, nil, paramsErr(problems)
	}
	doc, err := encode(defNode)
	if err != nil {
		return nil, nil, err
	}
	def, err := autodomain.Parse(doc)
	if err != nil {
		return nil, nil, fmt.Errorf("templates: %s renders an invalid definition: %w", id, err)
	}
	rawTests, err := encode(testsNode)
	if err != nil {
		return nil, nil, err
	}
	tests, err := buildTests(e.t.ID, def, rawTests)
	if err != nil {
		return nil, nil, fmt.Errorf("templates: %s: %w", id, err)
	}
	return doc, tests, nil
}

func encode(n *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
