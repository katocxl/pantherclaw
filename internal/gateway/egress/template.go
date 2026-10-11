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
	"net/url"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
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
	if len(t.Query) > 0 {
		q := url.Values{}
		for name, ref := range t.Query {
			v, err := r.queryValue(ref)
			if err != nil {
				return Request{}, err
			}
			if v != nil {
				q.Set(name, *v)
			}
		}
		u.RawQuery = q.Encode()
	}
	out := Request{Method: t.Method, URL: u}
	if len(t.Body) > 0 {
		obj := make(map[string]any, len(t.Body))
		for field, ref := range t.Body {
			v, err := r.value(ref)
			if err != nil {
				return Request{}, err
			}
			if v != nil {
				obj[field] = v
			}
		}
		if out.Body, err = json.Marshal(obj, json.Deterministic(true)); err != nil {
			return Request{}, fmt.Errorf("%w: %w", ErrBuild, err)
		}
		sum := sha256.Sum256(out.Body)
		out.BodySHA256 = sum[:]
	}
	if t.IdempotencyHeader != "" {
		out.IdempotencyHeader, out.IdempotencyKey = t.IdempotencyHeader, "pc-"+transaction
	}
	return out, nil
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

// queryValue is a reference substituted into one query parameter: nil for
// an absent optional param, otherwise its text, which url.Values encodes.
// Control characters are refused, as they are in a path (HR-073).
func (r refs) queryValue(ref string) (*string, error) {
	v, err := r.value(ref)
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
	case defs.TypeText:
	}
	return nil, fmt.Errorf("%w: untrusted text is never sent from a template", ErrBuild)
}
