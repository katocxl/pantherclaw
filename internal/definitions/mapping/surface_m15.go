// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// ErrUnsafeValue reports a resource URI that matches a reviewed template
// with a value that would change the upstream path (G0 M15 D44): it is
// refused before anything is decided.
var ErrUnsafeValue = fmt.Errorf("%w: a resource template value is empty, a dot segment, or holds a slash, a backslash or a control character",
	actionir.ErrAmbiguous)

// ResourceChannel is the channel of a resource read's action: it comes
// through the MCP face like a tool call (G0 M15 D30).
const ResourceChannel = domain.ChannelMCP

// Resource is a reviewed MCP resource or resource template the package
// maps, as MCP clients see it: the mapping's description and the
// definition's summary, never anything from the server (HR-419).
type Resource struct {
	// URI is the template; a static one is a single resource.
	URI         string
	Static      bool
	Route       string
	Operation   string
	Title       string
	Description string
}

// Resources lists the package's reviewed resources, by template.
func (m *Mapper) Resources() []Resource {
	out := make([]Resource, 0, len(m.resources))
	for _, c := range m.resources {
		out = append(out, Resource{
			URI: c.m.Resource, Static: c.resource.Static(), Route: c.m.Route, Operation: c.def.Operation,
			Title: c.def.Summary, Description: c.m.Description,
		})
	}
	slices.SortFunc(out, func(a, b Resource) int { return strings.Compare(a.URI, b.URI) })
	return out
}

// resource returns the one reviewed template uri matches, with the
// variables' values. ErrUnmapped: none matches (HR-419: the URI never
// reaches the server); ambiguous: more than one does; ErrUnsafeValue (with
// the template): a value domain.SafeValue refuses (D44).
func (m *Mapper) resource(uri string) (*compiled, map[string]any, error) {
	var match *compiled
	var vars map[string]any
	for _, c := range m.resources {
		vals, ok := c.resource.Match(uri)
		if !ok {
			continue
		}
		if match != nil {
			return nil, nil, ambiguous("resource %q matches more than one template", uri)
		}
		match, vars = c, map[string]any{}
		for k, v := range vals {
			vars[k] = v
		}
	}
	if match == nil {
		return nil, nil, fmt.Errorf("%w: resource %q", ErrUnmapped, uri)
	}
	for _, v := range vars {
		if s, _ := v.(string); !domain.SafeValue(s) {
			return match, nil, ErrUnsafeValue
		}
	}
	return match, vars, nil
}

// ResourceRoute returns the route and operation of the template uri
// matches, without mapping it; ok is false for none or more than one.
func (m *Mapper) ResourceRoute(uri string) (route, operation string, ok bool) {
	c, _, err := m.resource(uri)
	if c == nil || (err != nil && !errors.Is(err, ErrUnsafeValue)) {
		return "", "", false
	}
	return c.m.Route, c.def.Operation, true
}

// ReadResource maps a resources/read by URI into a read action: the
// template's variables are the extraction's path.<name>.
func (m *Mapper) ReadResource(ctx context.Context, tc Context, uri string) (actionir.Parsed, error) {
	c, vars, err := m.resource(uri)
	if err != nil {
		return actionir.Parsed{}, err
	}
	return m.run(ctx, tc, c, ResourceChannel, map[string]any{"input": map[string]any{}, "path": vars, "query": map[string]any{}}, nil)
}

// Elicitation returns the elicitation spec of an MCP tool's mapping, or
// nil when it declares none (G0 M15 D32).
func (m *Mapper) Elicitation(tool string) *domain.ElicitationSpec {
	if c, ok := m.mcp[tool]; ok {
		return c.m.Elicitation
	}
	return nil
}

// MCPAnswered maps a tools/call that carries elicitation answers (G0 M15
// D33): the arguments map as for MCP, and each answer, by field, must be
// one the tool's mapping declares, of its type; it becomes the material
// param elicitation.<field>. Anything else is ambiguous.
func (m *Mapper) MCPAnswered(ctx context.Context, tc Context, tool string, args []byte, answers domain.Values) (actionir.Parsed, error) {
	c, ok := m.mcp[tool]
	if !ok {
		return actionir.Parsed{}, fmt.Errorf("%w: tool %q", ErrUnmapped, tool)
	}
	e := c.m.Elicitation
	for _, name := range slices.Sorted(maps.Keys(answers)) {
		f, declared := e.Field(name)
		if !declared || f.Type != answers[name].Type {
			return actionir.Parsed{}, ambiguous("answer %q is not a declared elicitation field", name)
		}
	}
	input, err := DecodeInput(args)
	if err != nil {
		return actionir.Parsed{}, err
	}
	return m.run(ctx, tc, c, domain.ChannelMCP, map[string]any{"input": input, "path": map[string]any{}, "query": map[string]any{}}, answers)
}
