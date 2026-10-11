// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Dispatch says how a gateway sends an authorized action to its target
// (G0 M6 design decision 9, HR-075): the outbound request is built only
// from the canonical ActionIR fields the permit binds, never from the
// agent's original request. A definition without one cannot be proxied; a
// cooperative channel (the hook) dispatches nothing itself.
type Dispatch struct {
	HTTP *HTTPDispatch `json:"http,omitzero"`
	MCP  *MCPDispatch  `json:"mcp,omitzero"`
}

// HTTPDispatch is an outbound HTTP request template.
type HTTPDispatch struct {
	Method string `json:"method"`
	// Path is a template such as /v1/refunds/{target.id}: each segment is
	// literal or exactly one reference.
	Path string `json:"path"`
	// Body maps JSON body fields to references; a money param splits into
	// params.<name>.value and params.<name>.currency. No body when empty.
	Body map[string]string `json:"body,omitzero"`
	// IdempotencyHeader names the target's idempotency header; the gateway
	// fills it from the transaction (HR-008). Required when the definition
	// declares target_idempotency.
	IdempotencyHeader string `json:"idempotency_header,omitzero"`
	// Query maps query parameter names to references, as a path segment
	// takes them (identifiers, enums and integers); an absent optional
	// param leaves its parameter out (G0 M7 design decision 5). The
	// gateway encodes the values, and the built URL carries exactly these
	// names.
	Query map[string]string `json:"query,omitzero"`
}

// MCPDispatch is a call of one tool on an upstream (remote) MCP server.
type MCPDispatch struct {
	Tool      string            `json:"tool"`
	Arguments map[string]string `json:"arguments,omitzero"`
	// UpstreamDigest is "sha256:<hex>" of the canonical upstream tool
	// definition the package was reviewed against; a server announcing a
	// different definition is drift (HR-082).
	UpstreamDigest string `json:"upstream_digest"`
}

var (
	fieldRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	queryRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}(\[[a-z]{1,16}\])?$`)
	headerRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)
	digestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	dispatchSeg = regexp.MustCompile(`^([A-Za-z0-9._~-]+|\{[a-z][a-z0-9_.]{0,80}\})$`)
	// reservedHeaders are set by the gateway or carry credentials; a
	// package never names one.
	reservedHeaders = []string{
		"authorization", "proxy-authorization", "cookie", "host", "content-length", "content-type",
		"transfer-encoding", "connection", "te", "upgrade", "trailer", "keep-alive", "pap-action", "expect",
	}
)

const (
	maxTemplateFields = 64
	maxQueryParams    = 16
)

// bodiless methods send no body.
var bodiless = []string{"GET", "DELETE"}

// reference checks one template reference against the definition: the
// target id, a named group of its pattern (target.id.<group>), the account
// or a param. A path segment takes only an identifier, an enum or an
// integer.
func (d *Definition) reference(at, ref string, inPath bool) error {
	switch ref {
	case "target.id":
		return nil
	case "target.account":
		if d.Target.Account == PresenceNone {
			return invalid("%s: %s for a target without an account", at, ref)
		}
		return nil
	}
	if group, ok := strings.CutPrefix(ref, "target.id."); ok {
		if !d.Target.hasPart(group) {
			return invalid("%s: %s names no group of target.id_pattern", at, ref)
		}
		return nil
	}
	rest, ok := strings.CutPrefix(ref, "params.")
	if !ok {
		return invalid("%s: reference %q must be target.id, target.id.<group>, target.account or params.<name>", at, ref)
	}
	name, part, _ := strings.Cut(rest, ".")
	p, ok := d.Params[name]
	if !ok {
		return invalid("%s: reference to undeclared param %q", at, name)
	}
	switch {
	case p.Type == TypeText:
		return invalid("%s: untrusted text %q is never sent from a template", at, name)
	case p.Type == TypeMoney && part != "value" && part != "currency":
		return invalid("%s: money %q is sent as params.%s.value and params.%s.currency", at, name, name, name)
	case p.Type != TypeMoney && part != "":
		return invalid("%s: reference %q", at, ref)
	case inPath && !slices.Contains([]ParamType{TypeIdentifier, TypeEnum, TypeInteger}, p.Type):
		return invalid("%s: a path segment takes an identifier, enum or integer, not %s", at, p.Type)
	}
	return nil
}

// fields checks a body or arguments template.
func (d *Definition) fields(at string, f map[string]string) error {
	if len(f) > maxTemplateFields {
		return invalid("%s: at most %d fields", at, maxTemplateFields)
	}
	for _, k := range slices.Sorted(maps.Keys(f)) {
		if !fieldRe.MatchString(k) {
			return invalid("%s: field name %q", at, k)
		}
		if err := d.reference(at+"."+k, f[k], false); err != nil {
			return err
		}
	}
	return nil
}

func (d *Definition) validateDispatch() error {
	x := d.Dispatch
	if x == nil {
		return nil
	}
	at := d.Operation + ": dispatch"
	if (x.HTTP == nil) == (x.MCP == nil) {
		return invalid("%s: exactly one of http and mcp", at)
	}
	if h := x.HTTP; h != nil {
		if !slices.Contains(methods, h.Method) || !strings.HasPrefix(h.Path, "/") || len(h.Path) > 512 {
			return invalid("%s.http: a method %v and a path template starting with /", at, methods)
		}
		for _, seg := range strings.Split(h.Path[1:], "/") {
			if !dispatchSeg.MatchString(seg) || seg == "." || seg == ".." {
				return invalid("%s.http.path: segment %q", at, seg)
			}
			if strings.HasPrefix(seg, "{") {
				if err := d.reference(at+".http.path", seg[1:len(seg)-1], true); err != nil {
					return err
				}
			}
		}
		if err := d.fields(at+".http.body", h.Body); err != nil {
			return err
		}
		if slices.Contains(bodiless, h.Method) && len(h.Body) > 0 {
			return invalid("%s.http: %s sends no body", at, h.Method)
		}
		if len(h.Query) > maxQueryParams {
			return invalid("%s.http.query: at most %d parameters", at, maxQueryParams)
		}
		for _, name := range slices.Sorted(maps.Keys(h.Query)) {
			if !queryRe.MatchString(name) {
				return invalid("%s.http.query: parameter name %q", at, name)
			}
			if err := d.reference(at+".http.query."+name, h.Query[name], true); err != nil {
				return err
			}
		}
		switch hd := h.IdempotencyHeader; {
		case hd == "" && d.Retry.TargetIdempotency:
			return invalid("%s.http: target_idempotency needs an idempotency_header", at)
		case hd != "" && (!headerRe.MatchString(hd) || slices.Contains(reservedHeaders, strings.ToLower(hd))):
			return invalid("%s.http.idempotency_header %q", at, hd)
		}
	}
	if m := x.MCP; m != nil {
		if !toolRe.MatchString(m.Tool) {
			return invalid("%s.mcp.tool %q", at, m.Tool)
		}
		if !digestRe.MatchString(m.UpstreamDigest) {
			return invalid("%s.mcp.upstream_digest must be sha256:<64 hex>", at)
		}
		if err := d.fields(at+".mcp.arguments", m.Arguments); err != nil {
			return err
		}
	}
	return nil
}
