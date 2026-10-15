// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package engine evaluates detection rules over the event feed (G0 M10
// D10, HR-240). It is never on the decision path: a per-org job reads a
// batch of at most 500 events after the org's cursor, evaluates every
// enabled rule, raises signals and advances the cursor by compare-and-set
// in one transaction, so each feed entry is evaluated once per org.
// Evaluation cost is bounded by the CEL limits, the batch size and the
// cardinality caps; a rule that errors ten times in a row is disabled.
package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// EventType is the CEL type of the rule's one variable, event.
const EventType = "pc.reflex.Event"

var stringMap = types.NewMapType(types.StringType, types.StringType)

// schema is the event's CEL shape: the D2 fields. subjects maps a subject
// type to its first id; every field is always present (empty when
// unknown), so no has() guard is needed. attrs may lack a key: rules read
// it with `"k" in event.attrs` or event.attrs.?k.orValue("").
var schema = celenv.Schema{EventType: {Name: EventType, Fields: map[string]celenv.Field{
	"kind": {Type: types.StringType}, "actor_type": {Type: types.StringType}, "actor_id": {Type: types.StringType},
	"decision": {Type: types.StringType}, "reason": {Type: types.StringType}, "operation": {Type: types.StringType},
	"mode": {Type: types.StringType}, "outcome": {Type: types.StringType}, "environment": {Type: types.StringType},
	"destination_class": {Type: types.StringType}, "test": {Type: types.BoolType},
	"occurred_at": {Type: types.TimestampType}, "subjects": {Type: stringMap}, "attrs": {Type: stringMap},
}}}

// NewEnv returns the detection CEL environment with the given limits.
func NewEnv(limits celenv.Limits) (*celenv.Env, error) {
	return celenv.New(limits, schema, celenv.Variable{Name: "event", Type: types.NewObjectType(EventType)})
}

// Compiled is a validated rule with its conditions compiled.
type Compiled struct {
	Rule *rules.Rule
	// Digest is the hex SHA-256 of the rule's content; PackVersion is the
	// built-in pack's version (empty for a custom rule).
	Digest, PackVersion string
	match               *celenv.Program
	steps               []*celenv.Program
	window, horizon     time.Duration
	within              time.Duration
}

// Compile compiles r's conditions in env.
func Compile(env *celenv.Env, r *rules.Rule, digest, pack string) (*Compiled, error) {
	c := &Compiled{Rule: r, Digest: digest, PackVersion: pack}
	var err error
	if r.Match != "" {
		if c.match, err = env.Compile(r.Match, types.BoolType); err != nil {
			return nil, fmt.Errorf("%w: %s: match: %w", rules.ErrInvalid, r.ID, err)
		}
	}
	if s := r.Sequence; s != nil {
		for i, st := range s.Steps {
			var p *celenv.Program
			if st.Match != "" {
				if p, err = env.Compile(st.Match, types.BoolType); err != nil {
					return nil, fmt.Errorf("%w: %s: step %d: %w", rules.ErrInvalid, r.ID, i+1, err)
				}
			}
			c.steps = append(c.steps, p)
		}
		c.within, _ = time.ParseDuration(s.Within)
	}
	if r.Window != nil {
		c.window, _ = time.ParseDuration(r.Window.Duration)
	}
	if r.FirstSeen != nil {
		c.horizon, _ = time.ParseDuration(r.FirstSeen.Horizon)
	}
	return c, nil
}

// record is the CEL value of an event.
func record(e feed.Event) map[string]any {
	subjects := map[string]string{}
	for _, s := range e.Subjects {
		if _, ok := subjects[string(s.Type)]; !ok {
			subjects[string(s.Type)] = s.ID
		}
	}
	attrs := e.Attrs
	if attrs == nil {
		attrs = map[string]string{}
	}
	a := types.DefaultTypeAdapter
	return map[string]any{"event": &celenv.Record{TypeName: EventType, Fields: map[string]ref.Val{
		"kind": types.String(e.Kind), "actor_type": types.String(e.ActorType), "actor_id": types.String(e.ActorID),
		"decision": types.String(e.Decision), "reason": types.String(e.Reason), "operation": types.String(e.Operation),
		"mode": types.String(e.Mode), "outcome": types.String(e.Outcome), "environment": types.String(e.Environment),
		"destination_class": types.String(e.DestinationClass), "test": types.Bool(e.Test),
		"occurred_at": types.Timestamp{Time: e.OccurredAt}, "subjects": a.NativeToValue(subjects),
		"attrs": a.NativeToValue(attrs),
	}}}
}

func eval(ctx context.Context, p *celenv.Program, vars map[string]any) (bool, error) {
	if p == nil {
		return true, nil
	}
	ok, _, err := p.EvalBool(ctx, vars)
	return ok, err
}

// field reads a group_by, key or distinct field of e ("" when absent).
func field(e feed.Event, f string) string {
	switch f {
	case "kind":
		return e.Kind
	case "actor_type":
		return e.ActorType
	case "actor_id":
		return e.ActorID
	case "decision":
		return e.Decision
	case "reason":
		return e.Reason
	case "operation":
		return e.Operation
	case "mode":
		return e.Mode
	case "outcome":
		return e.Outcome
	case "environment":
		return e.Environment
	case "destination_class":
		return e.DestinationClass
	}
	if t, ok := strings.CutPrefix(f, "subjects."); ok {
		for _, s := range e.Subjects {
			if string(s.Type) == t {
				return s.ID
			}
		}
		return ""
	}
	if k, ok := strings.CutPrefix(f, "attrs."); ok {
		return e.Attrs[k]
	}
	return ""
}

// key joins the fields' values; ok is false when every value is empty.
func key(e feed.Event, fs []string) (string, bool) {
	if len(fs) == 0 {
		return "*", true
	}
	parts := make([]string, len(fs))
	some := false
	for i, f := range fs {
		parts[i] = f + "=" + field(e, f)
		some = some || field(e, f) != ""
	}
	k := strings.Join(parts, "|")
	if len(k) > 500 {
		k = k[:500]
	}
	return k, some
}
