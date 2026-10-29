// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
)

// A tools file declares a customer's own tools for the simulator as data
// (pantherclaw-sim mcp --tools FILE; G0 M17 D126, HR-468): each tool's name,
// description and input schema, and the results it answers. A result is
// chosen by an exact match of the call's arguments; nothing is computed,
// and the only thing copied from a call into a result is the arguments
// themselves (echo_args). Every result is marked simulated. Decoding is
// strict: an unknown member is an error.
//
//	{"tools": [{"name": "close_ticket", "description": "...", "inputSchema": {...},
//	  "results": [{"when": {"ticket": "T-1"}, "result": {"status": "closed"}}],
//	  "default": {"result": {"error": "not_found"}, "is_error": true, "echo_args": true}}]}
type ToolsFile struct {
	Tools []FileTool `json:"tools"`
}

// FileTool is one declared tool.
type FileTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema jsontext.Value `json:"inputSchema"`
	Results     []FileResult   `json:"results,omitempty"`
	// Default answers a call no result's when matches; without one, such a
	// call fails with no_simulated_result.
	Default *FileResult `json:"default,omitempty"`
}

// FileResult is one canned answer.
type FileResult struct {
	// When is the exact arguments object this result answers (compared in
	// canonical form). It is ignored on a default.
	When jsontext.Value `json:"when,omitempty"`
	// Result is a JSON object: the tool's structured content.
	Result  jsontext.Value `json:"result"`
	IsError bool           `json:"is_error,omitzero"`
	// EchoArgs adds the call's arguments to the result as "args".
	EchoArgs bool `json:"echo_args,omitzero"`
}

// Tools file limits.
const (
	MaxToolsFileBytes = 64 << 10
	MaxFileTools      = 64
	MaxToolResults    = 64
	maxDescription    = 4 << 10
)

var (
	fileToolName = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,120}$`)
	// builtinTools are the simulator's own tools: a file cannot redefine them.
	builtinTools = []string{"create_refund", "get_refund"}
)

// DeclaredTool is a validated tool of a tools file, its results keyed by
// canonical arguments.
type DeclaredTool struct {
	def      jsontext.Value // the tools/list entry
	results  map[string]FileResult
	fallback *FileResult
}

// LoadToolsFile reads and validates a tools file: a regular file of at
// most 64 KiB.
func LoadToolsFile(path string) (map[string]*DeclaredTool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > MaxToolsFileBytes {
		return nil, fmt.Errorf("tools file: a regular file of at most %d bytes", MaxToolsFileBytes)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen tools file
	if err != nil {
		return nil, err
	}
	return ParseToolsFile(raw)
}

// ParseToolsFile validates a tools file's content.
func ParseToolsFile(raw []byte) (map[string]*DeclaredTool, error) {
	if len(raw) == 0 || len(raw) > MaxToolsFileBytes {
		return nil, fmt.Errorf("tools file: size %d outside 1..%d bytes", len(raw), MaxToolsFileBytes)
	}
	var f ToolsFile
	if err := json.Unmarshal(raw, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("tools file: %w", err)
	}
	if len(f.Tools) == 0 || len(f.Tools) > MaxFileTools {
		return nil, fmt.Errorf("tools file: 1..%d tools", MaxFileTools)
	}
	out := make(map[string]*DeclaredTool, len(f.Tools))
	for _, t := range f.Tools {
		ft, err := t.compile()
		if err != nil {
			return nil, fmt.Errorf("tools file: tool %q: %w", t.Name, err)
		}
		if _, dup := out[t.Name]; dup || slices.Contains(builtinTools, t.Name) {
			return nil, fmt.Errorf("tools file: tool %q is declared twice or is a built-in tool", t.Name)
		}
		out[t.Name] = ft
	}
	return out, nil
}

func (t FileTool) compile() (*DeclaredTool, error) {
	switch {
	case !fileToolName.MatchString(t.Name):
		return nil, errors.New("name must match [A-Za-z0-9_.:/-]{1,120}")
	case len(t.Description) > maxDescription:
		return nil, fmt.Errorf("description longer than %d bytes", maxDescription)
	case t.InputSchema.Kind() != '{':
		return nil, errors.New("inputSchema must be a JSON object")
	case len(t.Results) > MaxToolResults:
		return nil, fmt.Errorf("at most %d results", MaxToolResults)
	}
	def, err := json.Marshal(struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		InputSchema jsontext.Value `json:"inputSchema"`
	}{t.Name, t.Description, t.InputSchema})
	if err != nil {
		return nil, err
	}
	ft := &DeclaredTool{def: def, results: map[string]FileResult{}}
	for i, r := range t.Results {
		if err := r.check(); err != nil {
			return nil, fmt.Errorf("result %d: %w", i+1, err)
		}
		key, err := canonicalArgs(r.When)
		if err != nil || r.When.Kind() != '{' {
			return nil, fmt.Errorf("result %d: when must be a JSON object", i+1)
		}
		if _, dup := ft.results[key]; dup {
			return nil, fmt.Errorf("result %d: the same when twice", i+1)
		}
		ft.results[key] = r
	}
	if t.Default != nil {
		if err := t.Default.check(); err != nil {
			return nil, fmt.Errorf("default: %w", err)
		}
		ft.fallback = t.Default
	}
	return ft, nil
}

func (r FileResult) check() error {
	if r.Result.Kind() != '{' {
		return errors.New("result must be a JSON object")
	}
	return nil
}

// canonicalArgs is the RFC 8785 form of an arguments object; no arguments
// is the empty object.
func canonicalArgs(v jsontext.Value) (string, error) {
	if len(bytes.TrimSpace(v)) == 0 {
		v = jsontext.Value(`{}`)
	}
	c := v.Clone()
	if err := c.Canonicalize(); err != nil {
		return "", err
	}
	return string(c), nil
}

// fileTools are the tools/list entries of the declared tools, in name order.
func (s *Server) fileTools() []jsontext.Value {
	names := make([]string, 0, len(s.f.Tools))
	for n := range s.f.Tools {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make([]jsontext.Value, 0, len(names))
	for _, n := range names {
		out = append(out, s.f.Tools[n].def)
	}
	return out
}

// fileCall answers a call of a declared tool; ok is false for any other
// tool. The result is the canned one, marked simulated (HR-468).
func (s *Server) fileCall(name string, args jsontext.Value) (map[string]any, bool) {
	t, ok := s.f.Tools[name]
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	key, err := canonicalArgs(args)
	if err != nil {
		return toolResult(true, map[string]any{"error": "invalid_arguments", "simulated": true}), true
	}
	r, ok := t.results[key]
	if !ok {
		if t.fallback == nil {
			return toolResult(true, map[string]any{"error": "no_simulated_result", "simulated": true}), true
		}
		r = *t.fallback
	}
	var body map[string]jsontext.Value
	if json.Unmarshal(r.Result, &body) != nil {
		return toolResult(true, map[string]any{"error": "invalid_result", "simulated": true}), true
	}
	body["simulated"] = jsontext.Value(`true`)
	if r.EchoArgs {
		body["args"] = jsontext.Value(key)
	}
	return toolResult(r.IsError, body), true
}
