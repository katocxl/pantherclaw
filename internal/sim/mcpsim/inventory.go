// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
)

// Discovery fixtures (G0 M15 D24): tools, resources and resource templates
// configured beyond the built-in ones, which a gateway reports in its
// connection's inventory.

// ExtraTool is a configured tool: it takes string arguments and answers
// them back.
type ExtraTool struct {
	Name, Description string
	// Params are its string parameters, all required.
	Params []string
}

// Resource is a listed resource.
type Resource struct {
	URI, Name, MimeType, Description string
}

// ResourceTemplate is a listed resource template.
type ResourceTemplate struct {
	URITemplate, Name, MimeType, Description string
}

// definition is the tool as tools/list lists it.
func (t ExtraTool) definition() jsontext.Value {
	props := map[string]any{}
	required := []string{}
	for _, p := range t.Params {
		props[p] = map[string]string{"type": "string"}
		required = append(required, p)
	}
	b, _ := json.Marshal(map[string]any{
		"name": t.Name, "description": t.Description,
		"inputSchema": map[string]any{"type": "object", "properties": props, "required": required},
	}, json.Deterministic(true))
	return b
}

// extraTools are the configured tools' definitions.
func (s *Server) extraTools() []jsontext.Value {
	out := make([]jsontext.Value, 0, len(s.f.Extra))
	for _, t := range s.f.Extra {
		out = append(out, t.definition())
	}
	return out
}

// callExtra runs a configured tool, reporting whether name is one.
func (s *Server) callExtra(name string, args map[string]string) (map[string]any, bool) {
	for _, t := range s.f.Extra {
		if t.Name != name {
			continue
		}
		s.mu.Lock()
		s.calls++
		s.mu.Unlock()
		return toolResult(false, map[string]any{"tool": name, "arguments": args, "simulated": true}), true
	}
	return nil, false
}

// lists answers resources/list and resources/templates/list, reporting
// whether method is one of them. Both page by Faults.PageSize.
func (s *Server) lists(method string, params jsontext.Value) (map[string]any, bool) {
	var items []any
	field := ""
	switch method {
	case "resources/list":
		field = "resources"
		for _, r := range s.f.Resources {
			items = append(items, map[string]string{"uri": r.URI, "name": r.Name, "mimeType": r.MimeType, "description": r.Description})
		}
	case "resources/templates/list":
		field = "resourceTemplates"
		for _, r := range s.f.Templates {
			items = append(items, map[string]string{
				"uriTemplate": r.URITemplate, "name": r.Name, "mimeType": r.MimeType, "description": r.Description,
			})
		}
	default:
		return nil, false
	}
	var p struct {
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(params, &p)
	from, _ := strconv.Atoi(p.Cursor)
	from = min(max(from, 0), len(items))
	to := len(items)
	if s.f.PageSize > 0 {
		to = min(from+s.f.PageSize, len(items))
	}
	out := map[string]any{field: append([]any{}, items[from:to]...)}
	if to < len(items) {
		out["nextCursor"] = strconv.Itoa(to)
	}
	return out, true
}

// hasResources reports whether the server lists resources or templates.
func (s *Server) hasResources() bool { return len(s.f.Resources)+len(s.f.Templates) > 0 }
