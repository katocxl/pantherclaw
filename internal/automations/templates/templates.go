// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package templates holds the governed-automation templates (G0 M11 part 2
// D32): nine embedded YAML definitions, each with typed, bounded template
// parameters and baseline tests (D34, HR-287).
//
// Render substitutes the parameters into the parsed YAML node tree, never
// into text: a value only ever replaces a whole `${name}` scalar, as a
// scalar (or a sequence of scalars for a list), so it cannot add keys,
// steps or `{{...}}` templates (T-126). The result is a definition
// document for autodomain.Parse and Validate, plus its baseline tests for
// the engine's simulator.
//
// A rendered document carries no name and no owner: the caller supplies
// both on the automation it creates from the template (D68).
package templates

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // timezone parameters name IANA zones; do not depend on the host's zone files

	"go.yaml.in/yaml/v3"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

//go:embed *.yaml
var files embed.FS

// Errors.
var (
	// ErrUnknown: no template has that id.
	ErrUnknown = errors.New("templates: unknown template")
	// ErrParams: template parameters are unknown, missing or invalid; the
	// message lists every one.
	ErrParams = errors.New("templates: invalid parameters")
)

// Param formats beyond the parameter's type.
const (
	FormatDate     = "date"     // YYYY-MM-DD
	FormatTimezone = "timezone" // an IANA zone
)

// Bounds of template parameters.
const (
	// DefaultMaxItems bounds a list parameter without max_items.
	DefaultMaxItems = 10
	maxItemsCap     = 50
)

// Param declares one template parameter: typed and bounded like a trigger
// parameter (autodomain.ParamSpec), optionally a comma-separated list.
type Param struct {
	Name        string               `yaml:"name" json:"name"`
	Description string               `yaml:"description" json:"description"`
	Type        autodomain.ParamType `yaml:"type" json:"type"`
	Format      string               `yaml:"format,omitempty" json:"format,omitzero"`
	Pattern     string               `yaml:"pattern,omitempty" json:"pattern,omitzero"`
	MaxLen      int                  `yaml:"max_len,omitempty" json:"max_len,omitzero"`
	Min         string               `yaml:"min,omitempty" json:"min,omitzero"`
	Max         string               `yaml:"max,omitempty" json:"max,omitzero"`
	Values      []string             `yaml:"values,omitempty" json:"values,omitzero"`
	// List: the value is a comma-separated list of at most MaxItems
	// distinct items, each of Type.
	List     bool `yaml:"list,omitempty" json:"list,omitzero"`
	MaxItems int  `yaml:"max_items,omitempty" json:"max_items,omitzero"`
	// Required (default true) parameters without a default must be given.
	// An optional parameter used by a chosen option must be given too.
	Required *bool  `yaml:"required,omitempty" json:"required,omitzero"`
	Default  string `yaml:"default,omitempty" json:"default,omitzero"`
	Example  string `yaml:"example,omitempty" json:"example,omitzero"`
	// Requires names parameters that must be set when this one is.
	Requires []string `yaml:"requires,omitempty" json:"requires,omitzero"`
}

// IsRequired reports whether the parameter must have a value.
func (p Param) IsRequired() bool { return p.Required == nil || *p.Required }

func (p Param) spec() autodomain.ParamSpec {
	return autodomain.ParamSpec{Type: p.Type, Pattern: p.Pattern, MaxLen: p.MaxLen, Min: p.Min, Max: p.Max, Values: p.Values}
}

func (p Param) maxItems() int {
	if p.MaxItems == 0 {
		return DefaultMaxItems
	}
	return p.MaxItems
}

// Template is one template's description.
type Template struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	// Kind is the rendered definition's work_kind (autodomain.WorkAgent or
	// autodomain.WorkSecurity).
	Kind    string             `json:"kind"`
	Edition autodomain.Edition `json:"edition"`
	Params  []Param            `json:"params"`
}

// Example returns a parameter set that renders: each parameter's example,
// or its default.
func (t Template) Example() map[string]string {
	out := map[string]string{}
	for _, p := range t.Params {
		if p.Example != "" {
			out[p.Name] = p.Example
		}
	}
	return out
}

func (t Template) clone() Template {
	t.Params = slices.Clone(t.Params)
	for i := range t.Params {
		t.Params[i].Values = slices.Clone(t.Params[i].Values)
		t.Params[i].Requires = slices.Clone(t.Params[i].Requires)
	}
	return t
}

// file is a template file as authored.
type file struct {
	ID         string    `yaml:"id"`
	Title      string    `yaml:"title"`
	Summary    string    `yaml:"summary"`
	Edition    string    `yaml:"edition"`
	Params     []Param   `yaml:"params"`
	Definition yaml.Node `yaml:"definition"`
	Tests      yaml.Node `yaml:"tests"`
}

// entry is a loaded template.
type entry struct {
	t      Template
	source []byte
	def    *yaml.Node
	tests  *yaml.Node
}

func (e *entry) param(name string) (Param, bool) {
	i := slices.IndexFunc(e.t.Params, func(p Param) bool { return p.Name == name })
	if i < 0 {
		return Param{}, false
	}
	return e.t.Params[i], true
}

var (
	idFormat    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	paramFormat = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// library loads the embedded templates once, on first use. A template
	// that does not load is a build defect; it is an error, never a panic
	// (G0 M11 D120): Load returns it to the server's start-up, which then
	// does not start, as it does without the engine's guard environment.
	library = sync.OnceValues(func() (map[string]*entry, error) { return load(files) })
)

// Load loads and checks every embedded template and returns the first
// defect. The server calls it at start-up; while it fails, List and Get
// find no template and Render returns its error.
func Load() error {
	_, err := library()
	return err
}

// loaded is the library, empty when it did not load.
func loaded() map[string]*entry {
	l, err := library()
	if err != nil {
		return nil
	}
	return l
}

// load reads and checks every embedded template.
func load(fsys fs.FS) (map[string]*entry, error) {
	names, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	lib := map[string]*entry{}
	for _, n := range names {
		raw, err := fs.ReadFile(fsys, n.Name())
		if err != nil {
			return nil, err
		}
		e, err := parseFile(raw)
		if err != nil {
			return nil, fmt.Errorf("templates: %s: %w", n.Name(), err)
		}
		if want := strings.TrimSuffix(n.Name(), path.Ext(n.Name())); e.t.ID != want {
			return nil, fmt.Errorf("templates: %s declares id %q", n.Name(), e.t.ID)
		}
		lib[e.t.ID] = e
	}
	return lib, nil
}

func parseFile(raw []byte) (*entry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(yaml.Node)); !errors.Is(err, io.EOF) {
		return nil, errors.New("one YAML document per template")
	}
	ed := autodomain.Edition(f.Edition)
	switch {
	case !idFormat.MatchString(f.ID):
		return nil, fmt.Errorf("id %q is not a lowercase identifier", f.ID)
	case strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Summary) == "":
		return nil, errors.New("a title and a summary are required")
	case ed != autodomain.EditionTeam && ed != autodomain.EditionBusiness:
		return nil, fmt.Errorf("edition %q is TEAM or BUSINESS", f.Edition)
	case f.Definition.Kind != yaml.MappingNode:
		return nil, errors.New("definition must be a mapping")
	case f.Tests.Kind != yaml.SequenceNode:
		return nil, errors.New("tests must be a sequence")
	}
	// The work kind is a literal of the definition, never a parameter.
	wk, ok := lookup(&f.Definition, "work_kind")
	if !ok || wk.Kind != yaml.ScalarNode || !autodomain.WorkKind(wk.Value).Valid() {
		return nil, errors.New("definition.work_kind is AGENT_WORK or SECURITY_WORK, written out")
	}
	e := &entry{
		t: Template{
			ID: f.ID, Title: f.Title, Summary: strings.TrimSpace(f.Summary), Kind: wk.Value,
			Edition: ed, Params: f.Params,
		},
		source: slices.Clone(raw), def: &f.Definition, tests: &f.Tests,
	}
	if err := e.checkParams(); err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for _, n := range []*yaml.Node{e.def, e.tests} {
		if err := e.checkDirectives(n, used); err != nil {
			return nil, err
		}
	}
	for _, p := range e.t.Params {
		if !used[p.Name] {
			return nil, fmt.Errorf("parameter %q is declared but never used", p.Name)
		}
	}
	return e, nil
}

// checkParams checks the declarations, defaults and examples.
func (e *entry) checkParams() error {
	seen := map[string]bool{}
	for _, p := range e.t.Params {
		switch {
		case !paramFormat.MatchString(p.Name):
			return fmt.Errorf("parameter %q is not a lowercase identifier", p.Name)
		case seen[p.Name]:
			return fmt.Errorf("parameter %q is declared twice", p.Name)
		case strings.TrimSpace(p.Description) == "":
			return fmt.Errorf("parameter %q needs a description", p.Name)
		case p.Type == autodomain.ParamString && p.Pattern == "":
			return fmt.Errorf("string parameter %q needs a pattern", p.Name)
		case p.Type == autodomain.ParamEnum && len(p.Values) == 0:
			return fmt.Errorf("enum parameter %q needs values", p.Name)
		case p.MaxItems < 0 || p.MaxItems > maxItemsCap || p.MaxItems > 0 && !p.List:
			return fmt.Errorf("parameter %q: max_items is 1 to %d, for lists", p.Name, maxItemsCap)
		case p.Format != "" && p.Format != FormatDate && p.Format != FormatTimezone:
			return fmt.Errorf("parameter %q: unknown format %q", p.Name, p.Format)
		case p.IsRequired() && p.Default == "" && p.Example == "":
			return fmt.Errorf("required parameter %q without a default needs an example", p.Name)
		}
		switch p.Type {
		case autodomain.ParamString, autodomain.ParamEnum, autodomain.ParamUUID, autodomain.ParamInt,
			autodomain.ParamDecimal, autodomain.ParamBool:
		default:
			return fmt.Errorf("parameter %q: unknown type %q", p.Name, p.Type)
		}
		seen[p.Name] = true
		for _, v := range []string{p.Default, p.Example} {
			if v == "" {
				continue
			}
			if _, err := convert(p, v); err != nil {
				return fmt.Errorf("parameter %q: %q: %w", p.Name, v, err)
			}
		}
	}
	for _, p := range e.t.Params {
		for _, r := range p.Requires {
			if !seen[r] || r == p.Name {
				return fmt.Errorf("parameter %q requires an undeclared parameter %q", p.Name, r)
			}
		}
	}
	return nil
}

// Directives of the template YAML; see render.go.
const (
	dirWhen   = "$when"
	dirValue  = "$value"
	dirSwitch = "$switch"
	dirCases  = "$cases"
)

var placeholder = regexp.MustCompile(`^\$\{([a-z][a-z0-9_]{0,31})\}$`)

// checkDirectives checks that every placeholder and directive names a
// declared parameter, that a switch covers every value of its enum or
// bool, and that no `$` appears anywhere else.
func (e *entry) checkDirectives(n *yaml.Node, used map[string]bool) error {
	at := func(format string, args ...any) error {
		return fmt.Errorf("line %d: "+format, append([]any{n.Line}, args...)...)
	}
	declared := func(name string) (Param, error) {
		p, ok := e.param(name)
		if !ok {
			return Param{}, at("parameter %q is not declared", name)
		}
		used[name] = true
		return p, nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if m := placeholder.FindStringSubmatch(n.Value); m != nil && n.Tag == "!!str" {
			_, err := declared(m[1])
			return err
		}
		if strings.Contains(n.Value, "${") || strings.HasPrefix(n.Value, "$") {
			return at("%q: a placeholder is a whole scalar ${name}", n.Value)
		}
		return nil
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if err := e.checkDirectives(c, used); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		if n.Anchor != "" {
			return at("anchors are not allowed")
		}
	case yaml.DocumentNode, yaml.AliasNode:
		return at("aliases and nested documents are not allowed")
	}
	keys := mappingKeys(n)
	if v, ok := lookup(n, dirSwitch); ok {
		if !slices.Equal(keys, []string{dirSwitch, dirCases}) {
			return at("a switch has exactly %s and %s", dirSwitch, dirCases)
		}
		p, err := declared(v.Value)
		if err != nil {
			return err
		}
		cases, _ := lookup(n, dirCases)
		if cases.Kind != yaml.MappingNode {
			return at("%s is a mapping", dirCases)
		}
		want := p.Values
		if p.Type == autodomain.ParamBool {
			want = []string{"false", "true"}
		}
		if p.Type != autodomain.ParamEnum && p.Type != autodomain.ParamBool || p.List {
			return at("a switch is on an enum or bool parameter")
		}
		if got := mappingKeys(cases); !sameSet(got, want) {
			return at("the cases of %q are %v; want every value %v", p.Name, got, want)
		}
		for i := 1; i < len(cases.Content); i += 2 {
			if err := e.checkDirectives(cases.Content[i], used); err != nil {
				return err
			}
		}
		return nil
	}
	if c, ok := lookup(n, dirWhen); ok {
		cond, err := decodeCond(c)
		if err != nil {
			return at("%v", err)
		}
		p, err := declared(cond.Param)
		if err != nil {
			return err
		}
		for _, v := range cond.In {
			if _, err := convert(p, v); err != nil {
				return at("%s: %q is not a value of %q", dirWhen, v, p.Name)
			}
		}
		if _, ok := lookup(n, dirValue); ok && len(keys) != 2 {
			return at("%s goes with %s alone", dirValue, dirWhen)
		}
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return at("keys are scalars")
		}
		switch k.Value {
		case dirWhen:
			continue
		case dirValue:
		default:
			if strings.Contains(k.Value, "$") {
				return at("key %q: keys are never substituted", k.Value)
			}
		}
		if err := e.checkDirectives(v, used); err != nil {
			return err
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

func mappingKeys(n *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, n.Content[i].Value)
	}
	return out
}

func lookup(n *yaml.Node, key string) (*yaml.Node, bool) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1], true
		}
	}
	return nil, false
}

// cond is a `$when` condition: the parameter is set (or not), or its
// value is one of In.
type cond struct {
	Param string
	Set   *bool
	In    []string
}

func decodeCond(n *yaml.Node) (cond, error) {
	var c cond
	if n.Kind != yaml.MappingNode {
		return c, fmt.Errorf("%s is a mapping {param, set | in}", dirWhen)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i].Value, n.Content[i+1]
		switch {
		case k == "param" && v.Kind == yaml.ScalarNode:
			c.Param = v.Value
		case k == "set" && v.Kind == yaml.ScalarNode && v.Tag == "!!bool":
			b := v.Value == "true"
			c.Set = &b
		case k == "in" && v.Kind == yaml.SequenceNode:
			for _, x := range v.Content {
				c.In = append(c.In, x.Value)
			}
		default:
			return c, fmt.Errorf("%s: unexpected %q", dirWhen, k)
		}
	}
	if c.Param == "" || (c.Set == nil) == (len(c.In) == 0) {
		return c, fmt.Errorf("%s names a param and exactly one of set or in", dirWhen)
	}
	return c, nil
}

// List returns every template, sorted by id.
func List() []Template {
	l := loaded()
	out := make([]Template, 0, len(l))
	for _, e := range l {
		out = append(out, e.t.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns the template with id.
func Get(id string) (Template, bool) {
	e, ok := loaded()[id]
	if !ok {
		return Template{}, false
	}
	return e.t.clone(), true
}

// Source returns template id's YAML as shipped: its parameter
// declarations, the definition with its placeholders and directives, and
// its baseline tests.
func Source(id string) ([]byte, bool) {
	e, ok := loaded()[id]
	if !ok {
		return nil, false
	}
	return slices.Clone(e.source), true
}

// convert checks one raw value (a whole list for list parameters) and
// returns its canonical items.
func convert(p Param, raw string) ([]string, error) {
	if strings.Contains(raw, "{{") || strings.Contains(raw, "}}") || strings.Contains(raw, "${") {
		return nil, errors.New("template syntax ({{, }} or ${) is not allowed in a value")
	}
	items := []string{raw}
	if p.List {
		items = strings.Split(raw, ",")
		if len(items) > p.maxItems() {
			return nil, fmt.Errorf("at most %d items", p.maxItems())
		}
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		v, err := p.spec().Convert(p.Name, it)
		if err != nil {
			// Drop the trigger-parameter wording ("automation: invalid
			// definition: parameter <name>: ").
			msg := strings.TrimPrefix(err.Error(), autodomain.ErrParam.Error()+" "+p.Name+": ")
			return nil, errors.New(msg)
		}
		txt := v.Text()
		switch p.Format {
		case FormatDate:
			if _, err := time.Parse(time.DateOnly, txt); err != nil {
				return nil, errors.New("a date is written YYYY-MM-DD")
			}
		case FormatTimezone:
			if _, err := time.LoadLocation(txt); err != nil || txt == "" || txt == "Local" {
				return nil, errors.New("not an IANA time zone")
			}
		}
		if slices.Contains(out, txt) {
			return nil, fmt.Errorf("%q is listed twice", txt)
		}
		out = append(out, txt)
	}
	return out, nil
}
