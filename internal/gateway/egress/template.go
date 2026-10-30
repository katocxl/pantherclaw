// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package egress is how the gateway reaches targets (G0 M6 design
// decisions 10 and 11, HR-070..076): the outbound request is built only
// from the canonical action a permit binds, through the reviewed dispatch
// template, onto the connection's own scheme, host and port; it is sent by
// a hardened client that never follows redirects and checks the connected
// address; and the response is capped, decompressed only within a ratio,
// and scrubbed of the credential before anything goes back to the agent.
package egress

import (
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// ErrBuild reports a request that cannot be built safely; nothing is sent
// (enforcement_failed).
var ErrBuild = errors.New("egress: the outbound request cannot be built from the action")

// Request is a built outbound request.
type Request struct {
	Method string
	URL    *url.URL
	// Body is the exact JSON body (nil for none), and BodySHA256 its hash,
	// which BeginDispatch records and an action token binds.
	Body       []byte
	BodySHA256 []byte
	// IdempotencyHeader, when the template names one, carries
	// IdempotencyKey, derived from the transaction (HR-008).
	IdempotencyHeader string
	IdempotencyKey    string
	// ContentType is the body's media type: JSON, or a form (G0 M14 D8).
	ContentType string
	// Headers are the template's literal static headers (D8).
	Headers map[string]string
}

// Build builds the outbound request of a definition's HTTP dispatch
// template (HR-073, HR-075) from the canonical action a permit binds:
// substitutions are path-escaped and may not contain separators, dot
// segments, "@", "#", "?", "%" or line breaks; the final URL is parsed
// again and must keep the connection's scheme, host, port and base path.
func Build(baseURL string, d *defs.Definition, a actionir.ActionIR, transaction string) (Request, error) {
	if d.Dispatch == nil || d.Dispatch.HTTP == nil {
		return Request{}, fmt.Errorf("%w: %s has no HTTP dispatch template", ErrBuild, d.Operation)
	}
	t := d.Dispatch.HTTP
	base, err := url.Parse(baseURL)
	if err != nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") || base.RawQuery != "" || base.User != nil {
		return Request{}, fmt.Errorf("%w: the connection's base URL", ErrBuild)
	}
	vals, err := d.DecodeParams(a.Params)
	if err != nil {
		return Request{}, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	r := refs{d: d, a: a, vals: vals}
	var path strings.Builder
	path.WriteString(strings.TrimSuffix(base.EscapedPath(), "/"))
	for _, seg := range strings.Split(strings.TrimPrefix(t.Path, "/"), "/") {
		path.WriteByte('/')
		if !strings.ContainsAny(seg, "{}") {
			path.WriteString(seg) // a reviewed literal ([A-Za-z0-9._~-])
			continue
		}
		if ref, ok := strings.CutSuffix(seg, "*}"); ok && strings.HasPrefix(ref, "{") {
			rest, err := r.rest(ref[1:])
			if err != nil {
				return Request{}, err
			}
			path.WriteString(rest)
			continue
		}
		if len(seg) < 3 || seg[0] != '{' || seg[len(seg)-1] != '}' {
			return Request{}, fmt.Errorf("%w: path segment %q", ErrBuild, seg)
		}
		v, err := r.segment(seg[1 : len(seg)-1])
		if err != nil {
			return Request{}, err
		}
		path.WriteString(url.PathEscape(v))
	}
	u, err := url.Parse(base.Scheme + "://" + base.Host + path.String())
	if err != nil || u.Scheme != base.Scheme || u.Host != base.Host || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		!strings.HasPrefix(u.EscapedPath(), strings.TrimSuffix(base.EscapedPath(), "/")+"/") {
		return Request{}, fmt.Errorf("%w: the built URL leaves the connection", ErrBuild)
	}
	var gc groupCount
	if len(t.Query) > 0 {
		q := url.Values{}
		for name, ref := range t.Query {
			v, err := r.queryValue(ref, &gc)
			if err != nil {
				return Request{}, err
			}
			if v != nil {
				q.Set(name, *v)
			}
		}
		u.RawQuery = q.Encode()
	}
	out := Request{Method: t.Method, URL: u, Headers: maps.Clone(t.Headers)}
	if len(t.Body) > 0 {
		obj, err := r.body(t.Body, transaction, t.Encoding != defs.EncodingForm, &gc)
		if err != nil {
			return Request{}, err
		}
		if t.Encoding == defs.EncodingForm {
			out.ContentType = FormContentType
			out.Body, err = EncodeForm(obj)
		} else {
			out.ContentType = JSONContentType
			if obj, err = nestJSON(obj); err == nil {
				out.Body, err = json.Marshal(obj, json.Deterministic(true))
			}
		}
		if err != nil {
			return Request{}, fmt.Errorf("%w: %w", ErrBuild, err)
		}
		sum := sha256.Sum256(out.Body)
		out.BodySHA256 = sum[:]
	}
	if gc.groups > 0 && gc.matched == 0 {
		return Request{}, fmt.Errorf("%w: no part of the target id is sent", ErrBuild)
	}
	if t.IdempotencyHeader != "" {
		out.IdempotencyHeader, out.IdempotencyKey = t.IdempotencyHeader, "pc-"+transaction
	}
	return out, nil
}

// groupCount counts the target-group references of a request's body and
// query and how many the target id matched (G0 M14 D49, D71).
type groupCount struct{ groups, matched int }

// group resolves a target.id.<group> body or query value: nil when the id
// left that alternative group unmatched, so the field is left out; an id
// that does not match its pattern at all builds nothing.
func (r refs) group(ref string, gc *groupCount) (any, error) {
	gc.groups++
	part, ok := r.d.Target.Part(r.a.Target.ID, strings.TrimPrefix(ref, "target.id."))
	if !ok {
		if !r.d.Target.MatchID(r.a.Target.ID) {
			return nil, fmt.Errorf("%w: the target id does not match its pattern", ErrBuild)
		}
		return nil, nil
	}
	gc.matched++
	return part, nil
}

// body resolves a body template's fields: a field referencing a target
// group the id left unmatched is left out; when every target-group field of
// the body and query is left out, nothing names the target and Build fails
// (G0 M14 D49).
func (r refs) body(fields map[string]string, transaction string, jsonBody bool, gc *groupCount) (map[string]any, error) {
	obj := make(map[string]any, len(fields))
	for field, ref := range fields {
		var v any
		var err error
		switch {
		case ref == defs.TransactionKey:
			v = "pc-" + transaction // G0 M14 D50
		case jsonBody && (ref == defs.BoolTrue || ref == defs.BoolFalse):
			v = ref == defs.BoolTrue // a JSON boolean, from the package only (G0 M20 D263, D272)
		case strings.HasPrefix(ref, "literal."):
			v = strings.TrimPrefix(ref, "literal.") // G0 M14 D52
		case strings.HasPrefix(ref, "target.id."):
			if v, err = r.group(ref, gc); err != nil {
				return nil, err
			}
		default:
			if v, err = r.value(ref); err != nil {
				return nil, err
			}
		}
		if v != nil {
			obj[field] = v
		}
	}
	return obj, nil
}

// BuildMCP builds the upstream tools/call of a definition's MCP dispatch
// template from the canonical action a permit binds: the reviewed upstream
// tool and its arguments object, each argument a reference resolved as an
// HTTP body field is (G0 M6 design decision 14).
func BuildMCP(d *defs.Definition, a actionir.ActionIR) (string, jsontext.Value, error) {
	if d.Dispatch == nil || d.Dispatch.MCP == nil {
		return "", nil, fmt.Errorf("%w: %s has no MCP dispatch template", ErrBuild, d.Operation)
	}
	vals, err := d.DecodeParams(a.Params)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	r := refs{d: d, a: a, vals: vals}
	args := make(map[string]any, len(d.Dispatch.MCP.Arguments))
	for name, ref := range d.Dispatch.MCP.Arguments {
		v, err := r.value(ref)
		if err != nil {
			return "", nil, err
		}
		if v != nil {
			args[name] = v
		}
	}
	b, err := json.Marshal(args, json.Deterministic(true))
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrBuild, err)
	}
	return d.Dispatch.MCP.Tool, b, nil
}

type refs struct {
	d    *defs.Definition
	a    actionir.ActionIR
	vals defs.Values
}

// unsafe are what a substitution may never contain (HR-073).
const unsafe = "/\\?#@%\r\n"

// segment is a reference substituted into one path segment.
func (r refs) segment(ref string) (string, error) {
	v, err := r.value(ref)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		if n, isNum := v.(jsontext.Value); isNum {
			s = string(n)
		} else {
			return "", fmt.Errorf("%w: %s is not a path value", ErrBuild, ref)
		}
	}
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, unsafe) {
		return "", fmt.Errorf("%w: %s would change the path", ErrBuild, ref)
	}
	return s, nil
}

// rest is a reference substituted into the rest of a path: each "/"-separated
// segment is checked as one segment is, then escaped (HR-073), so no
// value adds an empty or dot segment, a query or another host.
func (r refs) rest(ref string) (string, error) {
	v, err := r.value(ref)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%w: %s is not a path", ErrBuild, ref)
	}
	parts := strings.Split(s, "/")
	for i, p := range parts {
		if p == "" || p == "." || p == ".." || strings.ContainsAny(p, unsafe) {
			return "", fmt.Errorf("%w: %s would change the path", ErrBuild, ref)
		}
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/"), nil
}

// queryValue is a reference substituted into one query parameter: nil for
// an absent optional param, otherwise its text, which url.Values encodes.
// Control characters are refused, as they are in a path (HR-073).
func (r refs) queryValue(ref string, gc *groupCount) (*string, error) {
	var v any
	var err error
	switch {
	case strings.HasPrefix(ref, "literal."):
		v = strings.TrimPrefix(ref, "literal.") // G0 M14 D71
	case strings.HasPrefix(ref, "target.id."):
		v, err = r.group(ref, gc) // G0 M14 D71
	default:
		v, err = r.value(ref)
	}
	if err != nil || v == nil {
		return nil, err
	}
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case jsontext.Value:
		s = string(x)
	default:
		return nil, fmt.Errorf("%w: %s is not a query value", ErrBuild, ref)
	}
	if strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return nil, fmt.Errorf("%w: %s holds a control character", ErrBuild, ref)
	}
	return &s, nil
}

// value resolves one template reference to its JSON value: strings for
// identifiers, enums, text-like values and money parts, numbers for
// integers, booleans and lists as themselves. An optional param that is
// absent resolves to nil (the field is left out).
func (r refs) value(ref string) (any, error) {
	switch ref {
	case "target.id":
		return r.a.Target.ID, nil
	case "target.account":
		if r.a.Target.Account == "" {
			return nil, fmt.Errorf("%w: the action has no target account", ErrBuild)
		}
		return r.a.Target.Account, nil
	}
	if group, ok := strings.CutPrefix(ref, "target.id."); ok {
		part, ok := r.d.Target.Part(r.a.Target.ID, group)
		if !ok {
			return nil, fmt.Errorf("%w: the target id has no %s", ErrBuild, group)
		}
		return part, nil
	}
	rest, ok := strings.CutPrefix(ref, "params.")
	if !ok {
		return nil, fmt.Errorf("%w: reference %q", ErrBuild, ref)
	}
	name, part, _ := strings.Cut(rest, ".")
	v, ok := r.vals[name]
	if !ok {
		if p, declared := r.d.Params[name]; declared && !p.Required {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: params.%s has no value", ErrBuild, name)
	}
	switch v.Type {
	case defs.TypeMoney:
		switch part {
		case "value":
			return defs.FormatMoney(v.Money), nil
		case "currency":
			return string(v.Money.Currency), nil
		case "minor":
			// Integer minor units by the currency's exponent; an amount
			// finer than the minor unit, or a currency outside the list,
			// is refused (G0 M14 D8, CURRENCY_UNSUPPORTED).
			n, err := money.ToMinor(v.Money)
			if err != nil {
				return nil, fmt.Errorf("%w: params.%s in minor units: %w", ErrBuild, name, err)
			}
			return n, nil
		}
		return nil, fmt.Errorf("%w: reference %q", ErrBuild, ref)
	case defs.TypeInteger:
		return jsontext.Value(strconv.FormatInt(v.Int, 10)), nil
	case defs.TypeDecimal:
		return v.Decimal.String(), nil
	case defs.TypeBoolean:
		return v.Bool, nil
	case defs.TypeIdentifierList:
		return v.List, nil
	case defs.TypeEnum, defs.TypeIdentifier, defs.TypeCommand, defs.TypeContent, defs.TypePath:
		return v.Str, nil
	case defs.TypeText, defs.TypeQueryFilter:
	}
	return nil, fmt.Errorf("%w: untrusted text and query filters are never sent from a template", ErrBuild)
}
