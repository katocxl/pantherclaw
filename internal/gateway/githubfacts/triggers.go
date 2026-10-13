// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package githubfacts reads the github.* facts a decision needs from GitHub
// through the connection's App (G0 M8 decision 5, track G slice G4), and
// holds the deliberately small workflow parser behind the deploy_triggers
// facts (design decision 15): it understands push triggers, their branch
// filters and job environments, and skips the events no ref move can
// start. Any other event, and anything else that could change whether the
// operation deploys, makes the fact unknown, which holds the action, never
// "none" (HR-206).
package githubfacts

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Limits on what the parser reads (gateway configuration
// github.workflow_files, at most 20 files of at most 64 KiB each).
const (
	MaxWorkflowFiles = 20
	MaxWorkflowBytes = 64 << 10
	maxYAMLDepth     = 32
)

// Triggered is a workflow that a push to the branch starts.
type Triggered struct {
	Path         string   `json:"path"`
	Environments []string `json:"environments"`
}

// Triggers is the value of a deploy_triggers fact: whether a push to the
// branch starts a workflow that deploys to a GitHub environment. State is
// "triggered" only then; a workflow the push starts that names no
// environment (one deploying with repository secrets, say) is listed in
// Workflows with no environments while State stays "none", so consequence
// rules key on Workflows as well as Environments. Unknown, when set, is why
// that cannot be decided; State is then "unknown" too.
type Triggers struct {
	State        string      `json:"state"` // triggered, none or unknown
	Branch       string      `json:"branch"`
	At           string      `json:"at"`
	Workflows    []Triggered `json:"workflows"`
	Environments []string    `json:"environments"`
	Unknown      string      `json:"unknown,omitzero"`
}

// unknownError is a construct the parser does not evaluate.
type unknownError struct{ reason string }

func (e unknownError) Error() string { return e.reason }

func unknownf(format string, args ...any) error { return unknownError{fmt.Sprintf(format, args...)} }

// DeployTriggers decides, from the workflow files at a commit (path to
// content), whether a push to branch starts a workflow that deploys to an
// environment. A file it cannot evaluate makes the whole answer unknown.
// files must be every .github/workflows/*.yml and *.yaml file at the
// commit the operation leaves: the caller makes the answer unknown itself
// when it cannot list them all (a truncated or paged listing, more than
// MaxWorkflowFiles files) or read any one of them.
func DeployTriggers(files map[string][]byte, branch, at string) Triggers {
	out := Triggers{State: "none", Branch: branch, At: at, Workflows: []Triggered{}, Environments: []string{}}
	if len(files) > MaxWorkflowFiles {
		return out.unknown(fmt.Sprintf("more than %d workflow files", MaxWorkflowFiles))
	}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		envs, triggered, err := workflow(files[p], branch)
		if err != nil {
			return out.unknown(p + ": " + err.Error())
		}
		if !triggered {
			continue
		}
		out.Workflows = append(out.Workflows, Triggered{Path: p, Environments: envs})
		for _, e := range envs {
			if !slices.Contains(out.Environments, e) {
				out.Environments = append(out.Environments, e)
			}
		}
	}
	slices.Sort(out.Environments)
	if len(out.Environments) > 0 {
		out.State = "triggered"
	}
	return out
}

func (t Triggers) unknown(reason string) Triggers {
	t.State, t.Unknown, t.Workflows, t.Environments = "unknown", reason, []Triggered{}, []string{}
	return t
}

// workflow reports whether a push to branch starts the workflow, and the
// environments its jobs deploy to.
func workflow(raw []byte, branch string) ([]string, bool, error) {
	if len(raw) > MaxWorkflowBytes {
		return nil, false, unknownf("larger than %d bytes", MaxWorkflowBytes)
	}
	doc, err := parseYAML(raw)
	if err != nil {
		return nil, false, err
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil, false, unknownf("not a mapping")
	}
	triggered, err := pushTriggers(root["on"], branch)
	if err != nil || !triggered {
		return nil, false, err
	}
	envs, err := environments(root["jobs"])
	return envs, true, err
}

// unmoved are the events no ref move (a merge, a push, a branch creation,
// a file write) can start: a workflow on only these is not started by the
// operation. Every other event but push is unknown: a pull request closing
// on a merge (pull_request, pull_request_target), create and delete, the
// events chained from a push (merge_group, check_run, check_suite, status,
// deployment, deployment_status, page_build, workflow_run), release and
// repository_dispatch, and any event GitHub adds later.
var unmoved = map[string]bool{
	"schedule": true, "workflow_dispatch": true, "workflow_call": true, "issues": true, "issue_comment": true,
	"discussion": true, "discussion_comment": true, "label": true, "milestone": true, "watch": true, "fork": true,
	"gollum": true, "project": true, "project_card": true, "project_column": true, "public": true, "member": true,
	"pull_request_review": true, "pull_request_review_comment": true, "registry_package": true, "branch_protection_rule": true,
}

// pushTriggers evaluates the on: key for a push to branch.
func pushTriggers(on any, branch string) (bool, error) {
	var events map[string]any
	switch v := on.(type) {
	case nil:
		return false, unknownf("no on: key")
	case string:
		events = map[string]any{v: nil}
	case []any:
		events = map[string]any{}
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return false, unknownf("an event that is not a name")
			}
			events[s] = nil
		}
	case map[string]any:
		events = v
	default:
		return false, unknownf("on: is not an event, a list or a mapping")
	}
	for _, name := range slices.Sorted(maps.Keys(events)) {
		if name != "push" && !unmoved[name] {
			return false, unknownf("%s triggers are not evaluated", name)
		}
	}
	push, ok := events["push"]
	if !ok {
		return false, nil
	}
	if push == nil {
		return true, nil // every push
	}
	filters, ok := push.(map[string]any)
	if !ok {
		return false, unknownf("push: is not a mapping")
	}
	branches, hasBranches := filters["branches"]
	ignore, hasIgnore := filters["branches-ignore"]
	_, hasTags := filters["tags"]
	_, hasTagsIgnore := filters["tags-ignore"]
	switch {
	case hasBranches && hasIgnore:
		return false, unknownf("branches and branches-ignore together")
	case hasBranches:
		return matchList(branches, branch, false)
	case hasIgnore:
		return matchList(ignore, branch, true)
	case hasTags || hasTagsIgnore:
		return false, nil // only tags: branch pushes do not run it
	}
	return true, nil // paths filters and the like are not evaluated: assume it runs
}

// matchList applies a branches (or branches-ignore) filter to branch, in
// order, with ! negations, as GitHub does.
func matchList(list any, branch string, ignore bool) (bool, error) {
	var patterns []string
	switch v := list.(type) {
	case string:
		patterns = []string{v}
	case []any:
		for _, p := range v {
			s, ok := p.(string)
			if !ok {
				return false, unknownf("a branch filter that is not a string")
			}
			patterns = append(patterns, s)
		}
	default:
		return false, unknownf("a branch filter that is not a list")
	}
	matched := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		re, err := glob(strings.TrimPrefix(p, "!"))
		if err != nil {
			return false, err
		}
		if re.MatchString(branch) {
			matched = !neg
		}
	}
	if ignore {
		return !matched, nil
	}
	return matched, nil
}

// glob translates a GitHub filter pattern: * (anything but /), **
// (anything), ? and + (zero or one, and one or more, of the character
// before) and literal characters. Character classes, a ? or + after
// anything but a literal character, and expressions are not evaluated.
func glob(p string) (*regexp.Regexp, error) {
	refuse := unknownf("branch pattern %q is not evaluated", p)
	if p == "" || strings.ContainsAny(p, "[]\\") || strings.Contains(p, "${{") {
		return nil, refuse
	}
	if !utf8.ValidString(p) {
		return nil, refuse
	}
	var b strings.Builder
	b.WriteString("(?s)^")
	literal := false // the last token was one literal character
	rs := []rune(p)
	for i := 0; i < len(rs); i++ {
		switch c := rs[i]; {
		case c == '*' && i+1 < len(rs) && rs[i+1] == '*':
			b.WriteString(".*")
			i++
			literal = false
		case c == '*':
			b.WriteString("[^/]*")
			literal = false
		case c == '?' || c == '+':
			if !literal {
				return nil, refuse
			}
			b.WriteRune(c)
			literal = false
		default:
			b.WriteString("(?:" + regexp.QuoteMeta(string(c)) + ")")
			literal = true
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

// environments lists the environments the jobs deploy to. A reusable or
// remote workflow call, or an expression in an environment, is unknown.
func environments(jobs any) ([]string, error) {
	m, ok := jobs.(map[string]any)
	if !ok {
		return nil, unknownf("jobs: is not a mapping")
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(m)) {
		job, ok := m[name].(map[string]any)
		if !ok {
			return nil, unknownf("job %s is not a mapping", name)
		}
		if _, ok := job["uses"]; ok {
			return nil, unknownf("job %s calls a reusable workflow", name)
		}
		var env string
		switch e := job["environment"].(type) {
		case nil:
			continue
		case string:
			env = e
		case map[string]any:
			n, ok := e["name"].(string)
			if !ok {
				return nil, unknownf("job %s: environment without a name", name)
			}
			env = n
		default:
			return nil, unknownf("job %s: environment is not a name", name)
		}
		if strings.Contains(env, "${{") || env == "" {
			return nil, unknownf("job %s: environment %q is not evaluated", name, env)
		}
		if !slices.Contains(out, env) {
			out = append(out, env)
		}
	}
	slices.Sort(out)
	return out, nil
}

// parseYAML reads one YAML document with the M4 restrictions (HR-100): no
// anchors, aliases, merge keys or explicit tags, string keys, no duplicate
// keys, bounded depth. Scalars stay strings; null is nil.
func parseYAML(raw []byte) (any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, unknownf("not YAML: %v", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, unknownf("more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, unknownf("not one document")
	}
	return node(doc.Content[0], 1)
}

func node(n *yaml.Node, depth int) (any, error) {
	switch {
	case depth > maxYAMLDepth:
		return nil, unknownf("nested deeper than %d", maxYAMLDepth)
	case n.Kind == yaml.AliasNode || n.Anchor != "":
		return nil, unknownf("anchors and aliases are not evaluated")
	case n.Style&yaml.TaggedStyle != 0:
		return nil, unknownf("explicit tags are not evaluated")
	}
	switch n.Kind {
	case yaml.MappingNode:
		out := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" || k.Anchor != "" || k.Style&yaml.TaggedStyle != 0 {
				return nil, unknownf("line %d: keys must be plain strings", k.Line)
			}
			if _, dup := out[k.Value]; dup {
				return nil, unknownf("line %d: duplicate key %q", k.Line, k.Value)
			}
			v, err := node(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out[k.Value] = v
		}
		return out, nil
	case yaml.SequenceNode:
		out := []any{}
		for _, c := range n.Content {
			v, err := node(c, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return nil, nil
		}
		return n.Value, nil
	case yaml.DocumentNode, yaml.AliasNode:
	}
	return nil, unknownf("line %d: unexpected YAML node", n.Line)
}

// IsWorkflowPath reports whether a repository path is a workflow or action
// definition, whose change makes deploy triggers unknown.
func IsWorkflowPath(p string) bool {
	return strings.HasPrefix(p, ".github/workflows/") || strings.HasPrefix(p, ".github/actions/") ||
		path.Clean(p) == ".github/workflows" || path.Clean(p) == ".github/actions"
}
