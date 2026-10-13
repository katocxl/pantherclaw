// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// Struct type names of the policy environment.
const (
	actionType      = "pc.Action"
	targetType      = "pc.Target"
	paramsType      = "pc.Params"
	destinationType = "pc.Destination"
)

// celType is the CEL type of a parameter in policy conditions.
func celType(t defs.ParamType) *types.Type {
	switch t {
	case defs.TypeMoney:
		return celenv.MoneyType
	case defs.TypeDecimal:
		return celenv.DecimalType
	case defs.TypeInteger:
		return cel.IntType
	case defs.TypeBoolean:
		return cel.BoolType
	case defs.TypeIdentifierList:
		return cel.ListType(cel.StringType)
	case defs.TypeEnum, defs.TypeIdentifier, defs.TypeCommand, defs.TypeContent, defs.TypePath:
		return cel.StringType
	case defs.TypeText:
	}
	return nil
}

// ActionSchema is the typed shape of `action` for one definition:
//
//	action.operation, .channel, .route, .env           string
//	action.target.type, .id (.account if the target has one)
//	action.params.<name>                               typed per definition
//	action.destinations[i].kind, .id                   string
//	action.destination_class                           string: "public" or
//	                                                   "internal", the class of the action's connection
//	                                                   from the Authority's records (HR-079); "" without one
//
// Optional params and an optional account are optional fields (has()
// required, HR-042). Untrusted text params are not in the schema at all, so
// agent prose can never influence a rule (HR-023).
func ActionSchema(d *defs.Definition) celenv.Schema {
	params := map[string]celenv.Field{}
	for name, p := range d.Params {
		if t := celType(p.Type); t != nil {
			params[name] = celenv.Field{Type: t, Optional: !p.Required}
		}
	}
	target := map[string]celenv.Field{"type": {Type: cel.StringType}, "id": {Type: cel.StringType}}
	if d.Target.Account != defs.PresenceNone {
		target["account"] = celenv.Field{Type: cel.StringType, Optional: d.Target.Account == defs.PresenceOptional}
	}
	return celenv.Schema{
		actionType: {Name: actionType, Fields: map[string]celenv.Field{
			"operation": {Type: cel.StringType}, "channel": {Type: cel.StringType}, "route": {Type: cel.StringType},
			"env": {Type: cel.StringType}, "target": {Type: types.NewObjectType(targetType)},
			"params":            {Type: types.NewObjectType(paramsType)},
			"destinations":      {Type: cel.ListType(types.NewObjectType(destinationType))},
			"destination_class": {Type: cel.StringType},
		}},
		targetType:      {Name: targetType, Fields: target},
		paramsType:      {Name: paramsType, Fields: params},
		destinationType: {Name: destinationType, Fields: map[string]celenv.Field{"kind": {Type: cel.StringType}, "id": {Type: cel.StringType}}},
	}
}

// ActionVariable declares `action` for an environment built on ActionSchema.
var ActionVariable = celenv.Variable{Name: "action", Type: types.NewObjectType(actionType)}

// ActionRecord builds the runtime value of `action` from a parsed ActionIR,
// its decoded params and the destination class of its connection. Text
// params are left out (HR-023).
func ActionRecord(d *defs.Definition, a actionir.ActionIR, vals defs.Values, destinationClass string) *celenv.Record {
	params := map[string]ref.Val{}
	for name, v := range vals {
		if val := value(v); val != nil {
			params[name] = val
		}
	}
	target := map[string]ref.Val{"type": types.String(a.Target.Type), "id": types.String(a.Target.ID)}
	if a.Target.Account != "" && d.Target.Account != defs.PresenceNone {
		target["account"] = types.String(a.Target.Account)
	}
	dests := make([]ref.Val, len(a.Destinations))
	for i, dst := range a.Destinations {
		dests[i] = &celenv.Record{TypeName: destinationType, Fields: map[string]ref.Val{"kind": types.String(dst.Kind), "id": types.String(dst.ID)}}
	}
	return &celenv.Record{TypeName: actionType, Fields: map[string]ref.Val{
		"operation": types.String(a.Operation), "channel": types.String(a.Channel), "route": types.String(a.Route),
		"env":               types.String(a.Env),
		"target":            &celenv.Record{TypeName: targetType, Fields: target},
		"params":            &celenv.Record{TypeName: paramsType, Fields: params},
		"destinations":      types.NewRefValList(types.DefaultTypeAdapter, dests),
		"destination_class": types.String(destinationClass),
	}}
}

func value(v defs.Value) ref.Val {
	switch v.Type {
	case defs.TypeMoney:
		return celenv.Money{M: v.Money}
	case defs.TypeDecimal:
		return celenv.Decimal{D: v.Decimal}
	case defs.TypeInteger:
		return types.Int(v.Int)
	case defs.TypeBoolean:
		return types.Bool(v.Bool)
	case defs.TypeIdentifierList:
		return types.NewStringList(types.DefaultTypeAdapter, v.List)
	case defs.TypeEnum, defs.TypeIdentifier, defs.TypeCommand, defs.TypeContent, defs.TypePath:
		return types.String(v.Str)
	case defs.TypeText:
	}
	return nil
}

const factsType = "pc.Facts"

// factCELType is the CEL type of a fact value. Timestamps are integers
// (Unix seconds), compared with `now`.
func factCELType(t fdomain.Type) *types.Type {
	switch t {
	case fdomain.TypeBoolean:
		return cel.BoolType
	case fdomain.TypeInteger, fdomain.TypeTimestamp:
		return cel.IntType
	case fdomain.TypeDecimal:
		return celenv.DecimalType
	case fdomain.TypeMoney:
		return celenv.MoneyType
	case fdomain.TypeIdentifier:
		return cel.StringType
	case fdomain.TypeObject:
		// An object fact's members are read by name (facts.github_pull_head.sha);
		// a missing member is an evaluation error, which fails closed (HR-040).
		return cel.MapType(cel.StringType, cel.DynType)
	}
	return nil
}

// FactsSchema is the typed shape of `facts` for one rule: one field per
// fact it may read, named with dots as underscores. The fields are not
// optional, because a rule runs only when all of them are present.
func FactsSchema(names []string, catalog map[string]fdomain.Type) celenv.Schema {
	fields := map[string]celenv.Field{}
	for _, n := range names {
		if t := factCELType(catalog[n]); t != nil {
			fields[fdomain.CELName(n)] = celenv.Field{Type: t}
		}
	}
	return celenv.Schema{factsType: {Name: factsType, Fields: fields}}
}

// FactsVariable and NowVariable declare `facts` and `now` (decision time,
// Unix seconds, database clock).
var (
	FactsVariable = celenv.Variable{Name: "facts", Type: types.NewObjectType(factsType)}
	NowVariable   = celenv.Variable{Name: "now", Type: cel.IntType}
)

// FactsRecord builds the runtime value of `facts` from the values a rule may
// read.
func FactsRecord(names []string, have map[string]fdomain.Value) *celenv.Record {
	fields := map[string]ref.Val{}
	for _, n := range names {
		v, ok := have[n]
		if !ok {
			continue
		}
		var val ref.Val
		switch v.Type {
		case fdomain.TypeBoolean:
			val = types.Bool(v.Bool)
		case fdomain.TypeInteger, fdomain.TypeTimestamp:
			val = types.Int(v.Int)
		case fdomain.TypeDecimal:
			val = celenv.Decimal{D: v.Decimal}
		case fdomain.TypeMoney:
			val = celenv.Money{M: v.Money}
		case fdomain.TypeIdentifier:
			val = types.String(v.Str)
		case fdomain.TypeObject:
			val = types.DefaultTypeAdapter.NativeToValue(v.Object)
		}
		if val != nil {
			fields[fdomain.CELName(n)] = val
		}
	}
	return &celenv.Record{TypeName: factsType, Fields: fields}
}
