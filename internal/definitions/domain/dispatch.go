// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Dispatch says how a gateway sends an authorized action to its target
// (G0 M6 design decision 9, HR-075): the outbound request is built only
// from the canonical ActionIR fields the permit binds, never from the
// agent's original request. A definition without one cannot be proxied; a
// cooperative channel (the hook) dispatches nothing itself.
type Dispatch struct {
	HTTP *HTTPDispatch `json:"http,omitzero"`
	MCP  *MCPDispatch  `json:"mcp,omitzero"`
	// SQL is a structured read of a postgres connection (G0 M14 D9, D16);
	// A2A is a call to a peer agent (D9, D31). Each definition has
	// exactly one of http, mcp, sql and a2a.
	SQL *SQLDispatch `json:"sql,omitzero"`
	A2A *A2ADispatch `json:"a2a,omitzero"`
	// CredentialScope is the least privilege of the connection's credential
	// the operation needs, as name to level, which the credential kind
	// interprets (G0 M8): for a GitHub App, GitHub permission names and
	// levels, which the per-action installation token is minted with
	// (HR-203). A static credential ignores it.
	CredentialScope map[string]string `json:"credential_scope,omitzero"`
	// CredentialPattern is an anchored RE2 pattern the opened static
	// credential must match before any byte is sent; a mismatch refuses the
	// dispatch and sends nothing (G0 M14 D8, HR-301): a Stripe test key,
	// for example.
	CredentialPattern string `json:"credential_pattern,omitzero"`
}

// Scopes returns the dispatch's credential scope (nil without one).
func (d *Definition) Scopes() map[string]string {
	if d.Dispatch == nil {
		return nil
	}
	return d.Dispatch.CredentialScope
}

// HTTPDispatch is an outbound HTTP request template.
type HTTPDispatch struct {
	Method string `json:"method"`
	// Path is a template such as /v1/refunds/{target.id}: each segment is
	// literal or exactly one reference, except that the last may be
	// {params.<identifier>*}, the rest of the path from the param's value
	// (G0 M8: a file path), one checked and escaped segment per "/".
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
	// Encoding is how the body is sent: json (the default) or form
	// (application/x-www-form-urlencoded, with bracket keys such as a[b]
	// and a[]; G0 M14 D8, D52).
	Encoding Encoding `json:"encoding,omitzero"`
	// Headers are literal static headers sent on every request, such as
	// Stripe-Version: never a reserved header, never a reference (D8).
	Headers map[string]string `json:"headers,omitzero"`
	// Success, when set, is a top-level JSON boolean a 2xx answer must
	// carry with the given value, or the outcome is FAILED (D8: Slack's ok).
	Success *SuccessCheck `json:"success,omitzero"`
}

// MCPDispatch is a call of one tool on an upstream (remote) MCP server, or
// a read of one of its resources (G0 M15 D30).
type MCPDispatch struct {
	Tool string `json:"tool,omitzero"`
	// Resource is the upstream URI template a resource read is sent to: RFC
	// 6570 level 1, each variable a reference ({target.id}, {params.x}) the
	// gateway percent-encodes, so a value never changes the scheme or host
	// (HR-419). A resource dispatch has no tool or arguments.
	Resource  string            `json:"resource,omitzero"`
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
	scopeName   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	scopeLevel  = regexp.MustCompile(`^[a-z]{1,16}$`)
	dispatchSeg = regexp.MustCompile(`^([A-Za-z0-9._~-]+|\{[a-z][a-z0-9_.]{0,80}\})$`)
	// reservedHeaders are set by the gateway or carry credentials; a
	// package never names one.
	reservedHeaders = []string{
		"authorization", "proxy-authorization", "cookie", "host", "content-length", "content-type",
		"transfer-encoding", "connection", "te", "upgrade", "trailer", "keep-alive", "pap-action", "expect",
		"accept-encoding", // the gateway reads answers as identity (HR-076, G0 M14 D85)
	}
)

const (
	maxTemplateFields = 64
	maxQueryParams    = 16
)

// bodiless methods send no body.
var bodiless = []string{"GET", "DELETE"}

// place is where a template reference is substituted.
type place int

const (
	inPath place = iota
	inQuery
	inBody // an HTTP body field
	inArgs // an MCP argument
)

// literalRe is a literal.<value> body or query value: printable ASCII
// without braces (G0 M14 D52, D71).
var literalRe = regexp.MustCompile(`^[\x20-\x7a\x7c\x7e]{1,64}$`)

// TransactionKey is the reference to the action's idempotency value,
// "pc-<transaction>" (G0 M14 D50).
const TransactionKey = "transaction.key"

// reference checks one template reference against the definition: the
// target id, a named group of its pattern (target.id.<group>), the account
// or a param; in an HTTP body also the transaction key and literals. A
// path segment or query parameter takes only an identifier, an enum or an
// integer.
func (d *Definition) reference(at, ref string, where place) error {
	switch ref {
	case "target.id":
		return nil
	case "target.account":
		if d.Target.Account == PresenceNone {
			return invalid("%s: %s for a target without an account", at, ref)
		}
		return nil
	case TransactionKey:
		if where != inBody {
			return invalid("%s: %s is sent only as a body value", at, ref)
		}
		return nil
	}
	if lit, ok := strings.CutPrefix(ref, "literal."); ok {
		if (where != inBody && where != inQuery) || !literalRe.MatchString(lit) {
			return invalid("%s: a literal is a body or query value of 1..64 printable ASCII characters", at)
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
		return invalid("%s: reference %q must be target.id, target.id.<group>, target.account, params.<name>, "+
			"or in a body transaction.key or literal.<value>", at, ref)
	}
	name, part, _ := strings.Cut(rest, ".")
	p, ok := d.Params[name]
	if !ok {
		return invalid("%s: reference to undeclared param %q", at, name)
	}
	switch {
	case p.Type == TypeText:
		return invalid("%s: untrusted text %q is never sent from a template", at, name)
	case p.Type == TypeQueryFilter:
		return invalid("%s: query filter %q is applied by the gateway, never sent from a template", at, name)
	case p.Type == TypeMoney && part != "value" && part != "currency" && part != "minor":
		return invalid("%s: money %q is sent as params.%s.value, .currency or .minor", at, name, name)
	case p.Type != TypeMoney && part != "":
		return invalid("%s: reference %q", at, ref)
	case (where == inPath || where == inQuery) && !slices.Contains([]ParamType{TypeIdentifier, TypeEnum, TypeInteger}, p.Type):
		return invalid("%s: a path segment takes an identifier, enum or integer, not %s", at, p.Type)
	}
	if part == "minor" {
		for _, c := range p.Currencies {
			if _, err := money.MinorExponent(money.Currency(c)); err != nil {
				return invalid("%s: %s is not sent in minor units (CURRENCY_UNSUPPORTED)", at, c)
			}
		}
	}
	return nil
}

// fields checks a body or arguments template. A form body's keys may use
// the bracket syntax the form parser accepts (a[b], a[b][c], a[]); a list
// value goes only under a key ending in [] (G0 M14 D8, D52). A JSON HTTP
// body's keys may use the same grammar without [] to name nested objects
// (a[b][c] is {"a":{"b":{"c":…}}}, G0 M20 D260); MCP arguments stay flat.
func (d *Definition) fields(at string, f map[string]string, where place, enc Encoding) error {
	if len(f) > maxTemplateFields {
		return invalid("%s: at most %d fields", at, maxTemplateFields)
	}
	keys := slices.Sorted(maps.Keys(f))
	nested := where == inBody && enc != EncodingForm
	if enc == EncodingForm || nested {
		if err := CheckFormKeys(keys); err != nil {
			return invalid("%s: %v", at, err)
		}
	}
	for _, k := range keys {
		if nested && strings.Contains(k, "[") {
			if p, err := ParseFormKey(k); err != nil || p.List {
				return invalid("%s: field name %q: a JSON body nests objects only, never a [] list", at, k)
			}
		} else if enc != EncodingForm && !fieldRe.MatchString(k) {
			return invalid("%s: field name %q", at, k)
		}
		if err := d.reference(at+"."+k, f[k], where); err != nil {
			return err
		}
		if enc == EncodingForm {
			list := strings.HasSuffix(k, "[]")
			name, isParam := strings.CutPrefix(f[k], "params.")
			isList := isParam && d.Params[name].Type == TypeIdentifierList
			if isList != list && (!list || !strings.HasPrefix(f[k], "literal.")) {
				return invalid("%s.%s: a list goes, alone, under a key ending in []", at, k)
			}
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
	n := 0
	for _, set := range []bool{x.HTTP != nil, x.MCP != nil, x.SQL != nil, x.A2A != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return invalid("%s: exactly one of http, mcp, sql and a2a", at)
	}
	if len(x.CredentialScope) > 16 {
		return invalid("%s.credential_scope: at most 16 entries", at)
	}
	for _, name := range slices.Sorted(maps.Keys(x.CredentialScope)) {
		if !scopeName.MatchString(name) || !scopeLevel.MatchString(x.CredentialScope[name]) {
			return invalid("%s.credential_scope: %q: %q must be a lowercase name and level", at, name, x.CredentialScope[name])
		}
	}
	if p := x.CredentialPattern; p != "" {
		if len(p) > 128 {
			return invalid("%s.credential_pattern: at most 128 bytes", at)
		}
		if err := anchored(at+".credential_pattern", p); err != nil {
			return err
		}
	}
	if h := x.HTTP; h != nil {
		if err := d.validateHTTPDispatch(at+".http", h); err != nil {
			return err
		}
	}
	if m := x.MCP; m != nil && m.Resource != "" {
		if !digestRe.MatchString(m.UpstreamDigest) {
			return invalid("%s.mcp.upstream_digest must be sha256:<64 hex>", at)
		}
		if err := d.validateResourceDispatch(at+".mcp", m); err != nil {
			return err
		}
	} else if m != nil {
		if !toolRe.MatchString(m.Tool) {
			return invalid("%s.mcp.tool %q", at, m.Tool)
		}
		if !digestRe.MatchString(m.UpstreamDigest) {
			return invalid("%s.mcp.upstream_digest must be sha256:<64 hex>", at)
		}
		if err := d.fields(at+".mcp.arguments", m.Arguments, inArgs, EncodingJSON); err != nil {
			return err
		}
	}
	if s := x.SQL; s != nil {
		if !slices.Contains(SQLOperations, s.Operation) || d.Access != AccessRead {
			return invalid("%s.sql: a read with operation one of %v", at, SQLOperations)
		}
	}
	if a := x.A2A; a != nil && !slices.Contains(A2AMethods, a.Method) {
		return invalid("%s.a2a: method one of %v", at, A2AMethods)
	}
	return nil
}

func (d *Definition) validateHTTPDispatch(at string, h *HTTPDispatch) error {
	if !slices.Contains(methods, h.Method) || !strings.HasPrefix(h.Path, "/") || len(h.Path) > 512 {
		return invalid("%s: a method %v and a path template starting with /", at, methods)
	}
	segs := strings.Split(h.Path[1:], "/")
	for i, seg := range segs {
		if ref, ok := strings.CutSuffix(seg, "*}"); ok && strings.HasPrefix(seg, "{") {
			// The rest of the path from an identifier param, one segment
			// per "/" in its value, each checked and escaped by the gateway.
			if p, isParam := strings.CutPrefix(ref[1:], "params."); i != len(segs)-1 || !isParam || d.Params[p].Type != TypeIdentifier {
				return invalid("%s.path: %s must be the last segment and name an identifier param", at, seg)
			}
			continue
		}
		if !dispatchSeg.MatchString(seg) || seg == "." || seg == ".." {
			return invalid("%s.path: segment %q", at, seg)
		}
		if strings.HasPrefix(seg, "{") {
			if err := d.reference(at+".path", seg[1:len(seg)-1], inPath); err != nil {
				return err
			}
		}
	}
	switch h.Encoding {
	case EncodingDefault, EncodingJSON:
	case EncodingForm:
		if slices.Contains(bodiless, h.Method) {
			return invalid("%s: %s sends no body to encode as a form", at, h.Method)
		}
	default:
		return invalid("%s.encoding must be json or form", at)
	}
	if err := d.fields(at+".body", h.Body, inBody, h.Encoding); err != nil {
		return err
	}
	if slices.Contains(bodiless, h.Method) && len(h.Body) > 0 {
		return invalid("%s: %s sends no body", at, h.Method)
	}
	if len(h.Query) > maxQueryParams {
		return invalid("%s.query: at most %d parameters", at, maxQueryParams)
	}
	for _, name := range slices.Sorted(maps.Keys(h.Query)) {
		if !queryRe.MatchString(name) {
			return invalid("%s.query: parameter name %q", at, name)
		}
		if err := d.reference(at+".query."+name, h.Query[name], inQuery); err != nil {
			return err
		}
	}
	switch hd := h.IdempotencyHeader; {
	case hd == "" && d.Retry.TargetIdempotency:
		return invalid("%s: target_idempotency needs an idempotency_header", at)
	case hd != "" && (!headerRe.MatchString(hd) || slices.Contains(reservedHeaders, strings.ToLower(hd))):
		return invalid("%s.idempotency_header %q", at, hd)
	}
	if len(h.Headers) > maxStaticHeaders {
		return invalid("%s.headers: at most %d", at, maxStaticHeaders)
	}
	for _, name := range slices.Sorted(maps.Keys(h.Headers)) {
		lower := strings.ToLower(name)
		if !headerRe.MatchString(name) || slices.Contains(reservedHeaders, lower) || lower == strings.ToLower(h.IdempotencyHeader) ||
			lower == "idempotency-key" || // a fixed key would replay one answer for every action (D85)
			strings.HasPrefix(lower, "pap-") || strings.HasPrefix(lower, "pc-") || !staticHeaderRe.MatchString(h.Headers[name]) {
			return invalid("%s.headers: %q must be an unreserved header with a literal value of 1..128 printable ASCII characters", at, name)
		}
	}
	if s := h.Success; s != nil && !fieldRe.MatchString(s.Field) {
		return invalid("%s.success.field %q", at, s.Field)
	}
	return nil
}
