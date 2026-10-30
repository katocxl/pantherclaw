// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/hex"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// ChannelMCPResource maps an MCP resources/read onto a read operation
// (G0 M15 D30, HR-419): the mapping names an RFC 6570 level-1 URI
// template, and the URI an agent reads must match it. Its actions are
// channel mcp, like a tool call through the same face.
const ChannelMCPResource Channel = "mcp_resource"

// ElicitationSpec declares the fields an upstream MCP server may ask the
// agent for while it runs a tool (G0 M15 D32, HR-420). Each field becomes
// a material, optional param elicitation.<field> of the operation when the
// package is decoded, so policy and receipts see the answer; a request for
// anything else is refused.
type ElicitationSpec struct {
	Fields map[string]ParamSpec `json:"fields"`
}

// ElicitationPrefix starts the name of a param derived from an elicitation
// field.
const ElicitationPrefix = "elicitation."

// MaxElicitationFields bounds an elicitation spec.
const MaxElicitationFields = 16

// ElicitationTypes are the param types an elicitation field may have: the
// JSON types of an elicitation form (string, number, integer, boolean and
// enum).
var ElicitationTypes = []ParamType{TypeIdentifier, TypeContent, TypeEnum, TypeDecimal, TypeInteger, TypeBoolean}

// maxResourceTemplate bounds a resource URI template.
const maxResourceTemplate = 2048

var (
	// uriLiteralRe is the literal text of a URI template: RFC 3986 characters
	// other than the braces, with every % starting an escape.
	uriLiteralRe = regexp.MustCompile(`^([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$`)
	uriSchemeRe  = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}:`)
	uriVarRe     = regexp.MustCompile(`\{([^{}]*)\}`)
	// resourceVarRe is a mapping template's variable; dispatchVarRe a
	// dispatch template's, which names a reference (target.id, params.x).
	resourceVarRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	dispatchVarRe = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,80}$`)
	// uriValueRe is a variable's value in a URI: RFC 6570 simple expansion
	// percent-encodes everything but the unreserved characters.
	uriValueRe = regexp.MustCompile(`^([A-Za-z0-9\-._~]|%[0-9A-Fa-f]{2})+$`)
)

// URITemplate is a parsed RFC 6570 level-1 URI template: literal parts and
// {name} variables, alternating; Parts has one more element than Vars.
type URITemplate struct {
	Parts []string
	Vars  []string
}

// ParseURITemplate parses a level-1 URI template with an absolute scheme.
// varRe is the pattern of a variable name.
func parseURITemplate(at, s string, varRe *regexp.Regexp) (URITemplate, error) {
	if s == "" || len(s) > maxResourceTemplate || !uriSchemeRe.MatchString(s) {
		return URITemplate{}, invalid("%s: a URI template of at most %d bytes with a scheme", at, maxResourceTemplate)
	}
	var t URITemplate
	rest := s
	for {
		loc := uriVarRe.FindStringSubmatchIndex(rest)
		if loc == nil {
			break
		}
		t.Parts = append(t.Parts, rest[:loc[0]])
		name := rest[loc[2]:loc[3]]
		if !varRe.MatchString(name) {
			return URITemplate{}, invalid("%s: variable {%s}: only {name} variables (RFC 6570 level 1)", at, name)
		}
		if slices.Contains(t.Vars, name) {
			return URITemplate{}, invalid("%s: variable {%s} appears twice", at, name)
		}
		t.Vars = append(t.Vars, name)
		rest = rest[loc[1]:]
	}
	t.Parts = append(t.Parts, rest)
	for i, p := range t.Parts {
		if !uriLiteralRe.MatchString(p) {
			return URITemplate{}, invalid("%s: literal %q is not URI text", at, p)
		}
		if i > 0 && i < len(t.Parts)-1 && p == "" {
			return URITemplate{}, invalid("%s: two variables need a literal between them", at)
		}
	}
	if !uriSchemeRe.MatchString(t.Parts[0]) {
		return URITemplate{}, invalid("%s: the scheme is literal", at)
	}
	// The authority is literal too: a value never names the host (HR-419).
	if _, auth, ok := strings.Cut(t.Parts[0], "//"); ok && len(t.Vars) > 0 && !strings.ContainsAny(auth, "/?#") {
		return URITemplate{}, invalid("%s: the authority is literal and ends before the first variable", at)
	}
	return t, nil
}

// ParseResourceTemplate parses a mapping's resource template.
func ParseResourceTemplate(s string) (URITemplate, error) {
	return parseURITemplate("resource", s, resourceVarRe)
}

// Static reports a template without variables: a single resource.
func (t URITemplate) Static() bool { return len(t.Vars) == 0 }

// Match matches a URI against the template and returns each variable's
// decoded value. A value is one or more unreserved characters or escapes,
// as simple expansion writes it; it never spans a literal, so a value
// cannot reach into the scheme or authority the template fixes.
func (t URITemplate) Match(uri string) (map[string]string, bool) {
	rest, ok := strings.CutPrefix(uri, t.Parts[0])
	if !ok {
		return nil, false
	}
	vals := make(map[string]string, len(t.Vars))
	for i, name := range t.Vars {
		next := t.Parts[i+1]
		var raw string
		if i == len(t.Vars)-1 && next == "" {
			raw, rest = rest, ""
		} else {
			j := strings.Index(rest, next)
			if j < 0 {
				return nil, false
			}
			raw, rest = rest[:j], rest[j+len(next):]
		}
		if !uriValueRe.MatchString(raw) {
			return nil, false
		}
		v, ok := unescape(raw)
		if !ok {
			return nil, false
		}
		vals[name] = v
	}
	if rest != "" {
		return nil, false
	}
	return vals, true
}

// Expand builds the URI from values, percent-encoding each one (RFC 6570
// simple expansion): a value can never add a / , ? or # of its own.
func (t URITemplate) Expand(vals map[string]string) (string, bool) {
	var b strings.Builder
	b.WriteString(t.Parts[0])
	for i, name := range t.Vars {
		v, ok := vals[name]
		if !ok || v == "" {
			return "", false
		}
		b.WriteString(escape(v))
		b.WriteString(t.Parts[i+1])
	}
	return b.String(), true
}

func unreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		if c := s[i]; unreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

func unescape(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		c, err := hex.DecodeString(s[i+1 : i+3])
		if err != nil {
			return "", false
		}
		b.Write(c)
		i += 2
	}
	return b.String(), true
}

// ResourceTemplate returns the parsed template of an mcp_resource
// mapping, which validation accepted.
func (m Mapping) ResourceTemplate() (URITemplate, bool) {
	if m.Channel != ChannelMCPResource {
		return URITemplate{}, false
	}
	t, err := ParseResourceTemplate(m.Resource)
	return t, err == nil
}

// DispatchTemplate returns the parsed upstream URI template of a resource
// read, whose variables are references (target.id, params.<name>).
func (m *MCPDispatch) DispatchTemplate() (URITemplate, bool) {
	if m == nil || m.Resource == "" {
		return URITemplate{}, false
	}
	t, err := parseURITemplate("dispatch.mcp.resource", m.Resource, dispatchVarRe)
	return t, err == nil
}

// validateResourceMapping checks an mcp_resource mapping (D30): a resource
// template and nothing of the other channels, on a read without side
// effects that a resource dispatch sends.
func (d *Definition) validateResourceMapping(at string, m Mapping) error {
	if slices.ContainsFunc(d.Mappings, func(o Mapping) bool { return o.Channel != ChannelMCPResource }) {
		// One operation is a tool or a resource, never both (G0 M15 D36).
		return invalid("%s: an operation's mappings are all mcp_resource or none of them", at)
	}
	if m.Tool != "" || m.Method != "" || m.Path != "" || m.InputSchema != nil || m.Elicitation != nil {
		return invalid("%s: an mcp_resource mapping names a resource template and no tool, method, path, input_schema or elicitation", at)
	}
	if _, err := parseURITemplate(at+".resource", m.Resource, resourceVarRe); err != nil {
		return err
	}
	if d.Access != AccessRead || len(d.SideEffects) > 0 {
		return invalid("%s: a resource is a read without side effects", at)
	}
	if d.Dispatch == nil || d.Dispatch.MCP == nil || d.Dispatch.MCP.Resource == "" {
		return invalid("%s: a resource is read through a dispatch.mcp.resource template", at)
	}
	if m.Description != "" {
		if len(m.Description) > maxToolDescription {
			return invalid("%s: description longer than %d bytes", at, maxToolDescription)
		}
		return checkText(at+".description", m.Description)
	}
	return nil
}

// validateElicitation checks an mcp mapping's elicitation spec (D32).
func (d *Definition) validateElicitation(at string, e *ElicitationSpec) error {
	if e == nil {
		return nil
	}
	if len(e.Fields) == 0 || len(e.Fields) > MaxElicitationFields {
		return invalid("%s.elicitation: 1..%d fields", at, MaxElicitationFields)
	}
	for _, name := range slices.Sorted(maps.Keys(e.Fields)) {
		f := e.Fields[name]
		fat := at + ".elicitation.fields." + name
		switch {
		case !nameRe.MatchString(name):
			return invalid("%s: field name", fat)
		case !slices.Contains(ElicitationTypes, f.Type):
			return invalid("%s: an elicitation field is one of %v", fat, ElicitationTypes)
		case f.Required:
			return invalid("%s: an elicitation field is never required: the server may not ask", fat)
		}
		if err := f.Derived().validate(fat); err != nil {
			return err
		}
	}
	return nil
}

// Derived is the param an elicitation field becomes: material and
// optional.
func (p ParamSpec) Derived() ParamSpec {
	p.Material, p.Required = true, false
	return p
}

// validateResourceDispatch checks a resource read's upstream template: no
// tool or arguments, and each variable a reference a path segment may take.
func (d *Definition) validateResourceDispatch(at string, m *MCPDispatch) error {
	if m.Tool != "" || len(m.Arguments) > 0 {
		return invalid("%s: a resource dispatch names a resource template and no tool or arguments", at)
	}
	t, err := parseURITemplate(at+".resource", m.Resource, dispatchVarRe)
	if err != nil {
		return err
	}
	for _, ref := range t.Vars {
		if err := d.reference(at+".resource", ref, inPath); err != nil {
			return err
		}
	}
	if d.Access != AccessRead || slices.ContainsFunc(d.Mappings, func(mp Mapping) bool { return mp.Channel != ChannelMCPResource }) {
		return invalid("%s: a resource dispatch belongs to a read mapped only as a resource", at)
	}
	return nil
}

// elicitationField returns the spec of the elicitation field an mcp
// mapping of d declares under name, and whether one does.
func (d *Definition) elicitationField(name string) (ParamSpec, bool) {
	for _, m := range d.Mappings {
		if m.Elicitation != nil {
			if f, ok := m.Elicitation.Fields[name]; ok {
				return f.Derived(), true
			}
		}
	}
	return ParamSpec{}, false
}

// checkElicitationParam checks a param named elicitation.<field>: only a
// decoded package has one, derived from a declared field.
func (d *Definition) checkElicitationParam(name string) error {
	field, _ := strings.CutPrefix(name, ElicitationPrefix)
	f, ok := d.elicitationField(field)
	if !ok || !paramEqual(f, d.Params[name]) {
		return invalid("%s: param %q is derived from an elicitation field, never declared", d.Operation, name)
	}
	return nil
}

func paramEqual(a, b ParamSpec) bool {
	return a.Type == b.Type && a.Material == b.Material && a.Required == b.Required && a.Unit == b.Unit &&
		slices.Equal(a.Currencies, b.Currencies) && a.Min == b.Min && a.Max == b.Max && slices.Equal(a.Values, b.Values) &&
		a.Pattern == b.Pattern && a.MaxLength == b.MaxLength && a.MaxItems == b.MaxItems && a.Disclosure == b.Disclosure &&
		a.MaxBytes == b.MaxBytes && a.MaxEntropy == b.MaxEntropy
}

// validateElicitationFields checks that the mcp mappings of d declaring
// the same field declare it alike.
func (d *Definition) validateElicitationFields() error {
	seen := map[string]ParamSpec{}
	for _, m := range d.Mappings {
		if m.Elicitation == nil {
			continue
		}
		for name, f := range m.Elicitation.Fields {
			if prev, ok := seen[name]; ok && !paramEqual(prev, f) {
				return invalid("%s: elicitation field %q is declared twice, differently", d.Operation, name)
			}
			seen[name] = f
		}
	}
	return nil
}

// ExpandElicitation adds, to every definition, a material optional param
// elicitation.<field> for each elicitation field its mcp mappings declare
// (D32). The manifest decoder calls it after validation; the definition
// digest is of the file and does not change.
func (p *Package) ExpandElicitation() {
	for i := range p.Definitions {
		d := &p.Definitions[i]
		for _, m := range d.Mappings {
			if m.Elicitation == nil {
				continue
			}
			for name, f := range m.Elicitation.Fields {
				if d.Params == nil {
					d.Params = map[string]ParamSpec{}
				}
				d.Params[ElicitationPrefix+name] = f.Derived()
			}
		}
	}
}

// Field returns a declared field's spec (none on a nil spec).
func (e *ElicitationSpec) Field(name string) (ParamSpec, bool) {
	if e == nil {
		return ParamSpec{}, false
	}
	f, ok := e.Fields[name]
	return f, ok
}

// SafeValue reports whether a decoded template value may fill one segment
// (G0 M15 D44, HR-419), by the HTTP path builder's rule: never empty, "."
// or "..", and without "/", "\" or a control character, so no value adds
// a segment, climbs a path or splits a request.
func SafeValue(v string) bool {
	if v == "" || v == "." || v == ".." || strings.ContainsAny(v, `/\`) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// MatchResource matches uri against a reviewed mcp_resource template and
// returns each variable's decoded value: the one matcher the gateway's
// resources face and inventory coverage share (D31, D43 L5). ok is false
// for a template that does not parse, a URI it does not match, or a value
// SafeValue refuses.
func MatchResource(template, uri string) (vals map[string]string, ok bool) {
	t, err := ParseResourceTemplate(template)
	if err != nil {
		return nil, false
	}
	if vals, ok = t.Match(uri); !ok {
		return nil, false
	}
	for _, v := range vals {
		if !SafeValue(v) {
			return nil, false
		}
	}
	return vals, true
}

// authoredParams counts the params a package declares, without those
// derived from elicitation fields: only derived ones take the 16 extra
// slots (D44 L4).
func (d *Definition) authoredParams() int {
	n := 0
	for name := range d.Params {
		if !strings.HasPrefix(name, ElicitationPrefix) {
			n++
		}
	}
	return n
}
