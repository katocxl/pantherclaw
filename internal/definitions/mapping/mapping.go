// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mapping turns an MCP tool call or an HTTP request into ActionIR
// using the reviewed mappings of an ACTIVE tool package (PAP-1 §6, F375).
//
// Every extraction expression is compiled and type-checked when the package
// is loaded. At request time the input is decoded strictly, the expressions
// produce the target, parameters and destinations, the values are checked
// against the definition's declared types, the dedupe key is computed from
// the canonical result, and actionir.Encode produces the canonical bytes
// and hash. Anything missing, extra or ambiguous is actionir.ErrAmbiguous,
// which the Authority answers with CANNOT_AUTHORIZE, never a default
// (HR-100..103).
package mapping

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// ErrUnmapped reports a tool or route the package does not map. In enforce
// mode the Authority answers CANNOT_AUTHORIZE (unknown_route).
var ErrUnmapped = errors.New("mapping: no reviewed mapping for this call")

// Context carries the fields that never come from the agent: they are
// established by the gateway and the Authority (org, run, instance, and the
// connection the call came through).
type Context struct {
	Org, Env, RunID, ActionID, AgentInstance string
	Connection                               string
}

// Mapper maps calls for one package.
type Mapper struct {
	pkg  *domain.Package
	mcp  map[string]*compiled
	hook map[string]*compiled
	http []*compiled
}

type compiled struct {
	def      *domain.Definition
	m        domain.Mapping
	tmpl     []segment
	targetID *celenv.Program
	account  *celenv.Program
	params   map[string]*celenv.Program
	dests    []*celenv.Program
	// inputs are the top-level input fields the expressions read; any
	// other field in a request is ambiguous rather than silently dropped.
	inputs  []string
	queries []string
}

func newEnv(limits celenv.Limits) (*celenv.Env, error) {
	return celenv.New(limits, nil,
		celenv.Variable{Name: "input", Type: cel.MapType(cel.StringType, cel.DynType)},
		celenv.Variable{Name: "path", Type: cel.MapType(cel.StringType, cel.StringType)},
		celenv.Variable{Name: "query", Type: cel.MapType(cel.StringType, cel.StringType)},
	)
}

// New compiles every mapping of a validated package. A mapping whose
// expressions do not compile, return the wrong type or read their input in
// a way that cannot be analyzed is a package error.
func New(pkg *domain.Package, limits celenv.Limits) (*Mapper, error) {
	env, err := newEnv(limits)
	if err != nil {
		return nil, err
	}
	m := &Mapper{pkg: pkg, mcp: map[string]*compiled{}, hook: map[string]*compiled{}}
	for i := range pkg.Definitions {
		d := &pkg.Definitions[i]
		for _, mp := range d.Mappings {
			c, err := compile(env, d, mp)
			if err != nil {
				return nil, fmt.Errorf("%w: %s %s%s%s: %w", domain.ErrInvalid, d.Operation, mp.Tool, mp.Method, mp.Path, err)
			}
			switch mp.Channel {
			case domain.ChannelMCP:
				m.mcp[mp.Tool] = c
			case domain.ChannelHook:
				m.hook[mp.Tool] = c
			case domain.ChannelHTTP:
				m.http = append(m.http, c)
			case domain.ChannelSDK, domain.ChannelAuthZEN, domain.ChannelA2A:
				// Never a mapping's channel: package validation refuses it.
			}
		}
	}
	return m, nil
}

// paramType is the CEL type an extraction must produce for a param type.
func paramType(t domain.ParamType) *types.Type {
	switch t {
	case domain.TypeMoney:
		return celenv.MoneyType
	case domain.TypeDecimal:
		return celenv.DecimalType
	case domain.TypeInteger:
		return cel.IntType
	case domain.TypeBoolean:
		return cel.BoolType
	case domain.TypeIdentifierList:
		return cel.ListType(cel.StringType)
	case domain.TypeEnum, domain.TypeIdentifier, domain.TypeText, domain.TypeCommand, domain.TypeContent, domain.TypePath:
		return cel.StringType
	}
	return nil
}

// fits accepts the declared type, dyn (checked at runtime), or an optional
// of either when the value may be absent.
func fits(got, want *types.Type, optional bool) bool {
	if got.IsExactType(want) || got.IsExactType(cel.DynType) {
		return true
	}
	if optional && got.Kind() == types.OpaqueKind && got.TypeName() == "optional_type" && len(got.Parameters()) == 1 {
		return fits(got.Parameters()[0], want, false)
	}
	return false
}

func compile(env *celenv.Env, d *domain.Definition, mp domain.Mapping) (*compiled, error) {
	c := &compiled{def: d, m: mp, params: map[string]*celenv.Program{}}
	if mp.Channel == domain.ChannelHTTP {
		c.tmpl = parseTemplate(mp.Path)
	}
	var progs []*celenv.Program
	expr := func(name, src string, want *types.Type, optional bool) (*celenv.Program, error) {
		p, err := env.Compile(src, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if !fits(p.OutputType(), want, optional) {
			return nil, fmt.Errorf("%s: expression returns %s, want %s", name, p.OutputType(), want)
		}
		progs = append(progs, p)
		return p, nil
	}
	var err error
	if c.targetID, err = expr("target_id", mp.Extract.TargetID, cel.StringType, false); err != nil {
		return nil, err
	}
	if mp.Extract.TargetAccount != "" {
		if c.account, err = expr("target_account", mp.Extract.TargetAccount, cel.StringType, d.Target.Account == domain.PresenceOptional); err != nil {
			return nil, err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(mp.Extract.Params)) {
		spec := d.Params[name]
		if c.params[name], err = expr("params."+name, mp.Extract.Params[name], paramType(spec.Type), !spec.Required); err != nil {
			return nil, err
		}
	}
	for i, dst := range mp.Extract.Destinations {
		p, err := expr(fmt.Sprintf("destinations[%d]", i), dst.ID, cel.StringType, false)
		if err != nil {
			return nil, err
		}
		c.dests = append(c.dests, p)
	}
	for _, p := range progs {
		fields, ok := p.Fields("input")
		if !ok {
			return nil, fmt.Errorf("%q must read input only by field (input.f, input.?f, has(input.f))", p.Source())
		}
		c.inputs = append(c.inputs, fields...)
		queries, ok := p.Fields("query")
		if !ok {
			return nil, fmt.Errorf("%q must read query only by field", p.Source())
		}
		c.queries = append(c.queries, queries...)
		if vars, ok := p.Fields("path"); !ok || slices.ContainsFunc(vars, func(v string) bool { return !c.hasPathVar(v) }) {
			return nil, fmt.Errorf("%q reads a path variable the template does not declare", p.Source())
		}
	}
	slices.Sort(c.inputs)
	c.inputs = slices.Compact(c.inputs)
	slices.Sort(c.queries)
	c.queries = slices.Compact(c.queries)
	return c, nil
}

func (c *compiled) hasPathVar(v string) bool {
	return slices.ContainsFunc(c.tmpl, func(s segment) bool { return s.param == v })
}

// MCP maps a tools/call by tool name and JSON arguments.
func (m *Mapper) MCP(ctx context.Context, tc Context, tool string, args []byte) (actionir.Parsed, error) {
	return m.byName(ctx, tc, m.mcp, tool, args, domain.ChannelMCP)
}

// Hook maps a cooperative client's call (the Claude Code hook) by its kind
// and JSON input.
func (m *Mapper) Hook(ctx context.Context, tc Context, kind string, input []byte) (actionir.Parsed, error) {
	return m.byName(ctx, tc, m.hook, kind, input, domain.ChannelHook)
}

// SDK maps an agent SDK's tool call (the gateway's /sdk face, HR-201)
// through the package's MCP mapping of the tool, by tool name and JSON
// input, exactly as the MCP face maps it except that the action's channel
// is sdk (F099). Shell commands go through the hook face (HR-200).
func (m *Mapper) SDK(ctx context.Context, tc Context, tool string, input []byte) (actionir.Parsed, error) {
	return m.byName(ctx, tc, m.mcp, tool, input, domain.ChannelSDK)
}

// Tool is an MCP tool the package maps, with the operation it maps to.
type Tool struct {
	Tool      string `json:"tool"`
	Operation string `json:"operation"`
}

// Tools lists exactly the MCP tools the package maps, which SDK calls
// map through too, by tool name.
func (m *Mapper) Tools() []Tool {
	out := make([]Tool, 0, len(m.mcp))
	for name, c := range m.mcp {
		out = append(out, Tool{Tool: name, Operation: c.def.Operation})
	}
	slices.SortFunc(out, func(a, b Tool) int { return strings.Compare(a.Tool, b.Tool) })
	return out
}

// byName maps a call by tool name into an action of the given channel.
func (m *Mapper) byName(ctx context.Context, tc Context, by map[string]*compiled, tool string, args []byte, channel domain.Channel) (actionir.Parsed, error) {
	c, ok := by[tool]
	if !ok {
		return actionir.Parsed{}, fmt.Errorf("%w: tool %q", ErrUnmapped, tool)
	}
	input, err := DecodeInput(args)
	if err != nil {
		return actionir.Parsed{}, err
	}
	return m.run(ctx, tc, c, channel, map[string]any{"input": input, "path": map[string]any{}, "query": map[string]any{}})
}

// HTTP maps a request by method, raw (escaped) path, raw query and body.
// More than one matching route is ambiguous.
func (m *Mapper) HTTP(ctx context.Context, tc Context, method, rawPath, rawQuery string, body []byte) (actionir.Parsed, error) {
	var match *compiled
	var vars map[string]any
	for _, c := range m.http {
		if c.m.Method != method {
			continue
		}
		if v, ok := matchPath(c.tmpl, rawPath); ok {
			if match != nil {
				return actionir.Parsed{}, ambiguous("%s %s matches more than one route", method, rawPath)
			}
			match, vars = c, v
		}
	}
	if match == nil {
		return actionir.Parsed{}, fmt.Errorf("%w: %s %s", ErrUnmapped, method, rawPath)
	}
	query, err := parseQuery(rawQuery)
	if err != nil {
		return actionir.Parsed{}, err
	}
	input, err := DecodeInput(body)
	if err != nil {
		return actionir.Parsed{}, err
	}
	return m.run(ctx, tc, match, domain.ChannelHTTP, map[string]any{"input": input, "path": vars, "query": query})
}

// HTTPRoute returns the route id a request's method and raw path match,
// without mapping its input; ok is false for none or more than one. It
// names the route of a request that is refused before mapping.
func (m *Mapper) HTTPRoute(method, rawPath string) (route string, ok bool) {
	for _, c := range m.http {
		if c.m.Method != method {
			continue
		}
		if _, match := matchPath(c.tmpl, rawPath); match {
			if ok {
				return "", false
			}
			route, ok = c.m.Route, true
		}
	}
	return route, ok
}

func (m *Mapper) run(ctx context.Context, tc Context, c *compiled, channel domain.Channel, vars map[string]any) (actionir.Parsed, error) {
	input, _ := vars["input"].(map[string]any)
	for k := range input {
		if _, found := slices.BinarySearch(c.inputs, k); !found {
			return actionir.Parsed{}, ambiguous("input field %q is not part of the reviewed mapping", k)
		}
	}
	query, _ := vars["query"].(map[string]any)
	for k := range query {
		if _, found := slices.BinarySearch(c.queries, k); !found {
			return actionir.Parsed{}, ambiguous("query parameter %q is not part of the reviewed mapping", k)
		}
	}
	target := actionir.Target{Type: c.def.Target.Type}
	var err error
	if target.ID, err = evalString(ctx, c.targetID, vars); err != nil {
		return actionir.Parsed{}, ambiguous("target_id: %v", err)
	}
	if c.account != nil {
		if target.Account, err = evalString(ctx, c.account, vars); err != nil {
			return actionir.Parsed{}, ambiguous("target_account: %v", err)
		}
	}
	if !c.def.Target.MatchID(target.ID) || !c.def.Target.MatchAccount(target.Account) {
		return actionir.Parsed{}, ambiguous("target does not match the definition's identity pattern")
	}
	vals := domain.Values{}
	for name, p := range c.params {
		v, present, err := evalParam(ctx, p, c.def.Params[name].Type, vars)
		if err != nil {
			return actionir.Parsed{}, ambiguous("params.%s: %v", name, err)
		}
		if present {
			vals[name] = v
		}
	}
	params, err := c.def.EncodeParams(vals)
	if err != nil {
		return actionir.Parsed{}, err
	}
	dests := []actionir.Destination{}
	for i, p := range c.dests {
		id, err := evalString(ctx, p, vars)
		if err != nil {
			return actionir.Parsed{}, ambiguous("destinations[%d]: %v", i, err)
		}
		dests = append(dests, actionir.Destination{Kind: c.m.Extract.Destinations[i].Kind, ID: id})
	}
	dedupe, err := c.def.DedupeKey(target, vals)
	if err != nil {
		return actionir.Parsed{}, err
	}
	return actionir.Encode(actionir.ActionIR{
		V: actionir.Version, Org: tc.Org, Env: tc.Env, RunID: tc.RunID, ActionID: tc.ActionID, AgentInstance: tc.AgentInstance, Connection: tc.Connection,
		Operation:  c.def.Operation,
		Definition: actionir.Definition{Package: m.pkg.Name, Version: m.pkg.Version, Digest: c.def.Digest},
		Channel:    string(channel), Route: c.m.Route, Target: target, Params: params,
		Destinations: dests, DedupeKey: dedupe,
	})
}

func evalString(ctx context.Context, p *celenv.Program, vars map[string]any) (string, error) {
	v, present, err := eval(ctx, p, vars)
	if err != nil {
		return "", err
	}
	if !present {
		return "", errors.New("no value")
	}
	s, ok := v.(types.String)
	if !ok {
		return "", fmt.Errorf("got %s, want string", v.Type().TypeName())
	}
	return string(s), nil
}

// eval runs an extraction and unwraps optionals: an empty optional is
// "absent", which is an error wherever a value is required.
func eval(ctx context.Context, p *celenv.Program, vars map[string]any) (ref.Val, bool, error) {
	v, _, err := p.Eval(ctx, vars)
	if err != nil {
		return nil, false, err
	}
	if o, ok := v.(*types.Optional); ok {
		if !o.HasValue() {
			return nil, false, nil
		}
		v = o.GetValue()
	}
	return v, true, nil
}

func evalParam(ctx context.Context, p *celenv.Program, t domain.ParamType, vars map[string]any) (domain.Value, bool, error) {
	v, present, err := eval(ctx, p, vars)
	if err != nil || !present {
		return domain.Value{}, false, err
	}
	out := domain.Value{Type: t}
	ok := false
	switch t {
	case domain.TypeMoney:
		var m celenv.Money
		m, ok = v.(celenv.Money)
		out.Money = m.M
	case domain.TypeDecimal:
		var d celenv.Decimal
		d, ok = v.(celenv.Decimal)
		out.Decimal = d.D
	case domain.TypeInteger:
		var n types.Int
		n, ok = v.(types.Int)
		out.Int = int64(n)
	case domain.TypeBoolean:
		var b types.Bool
		b, ok = v.(types.Bool)
		out.Bool = bool(b)
	case domain.TypeEnum, domain.TypeIdentifier, domain.TypeText, domain.TypeCommand, domain.TypeContent, domain.TypePath:
		var s types.String
		s, ok = v.(types.String)
		out.Str = string(s)
	case domain.TypeIdentifierList:
		out.List, ok = stringList(v)
	}
	if !ok {
		return domain.Value{}, false, fmt.Errorf("got %s, want %s", v.Type().TypeName(), t)
	}
	return out, true, nil
}

func stringList(v ref.Val) ([]string, bool) {
	native, err := v.ConvertToNative(reflectStrings)
	if err != nil {
		return nil, false
	}
	l, ok := native.([]string)
	return l, ok
}

var reflectStrings = reflect.TypeOf([]string(nil))
