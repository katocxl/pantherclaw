// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"fmt"
	"maps"
	"sync"
	"time"

	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// CEL types of the trigger expressions (D2, D18, D19): `where` of an event
// or threshold trigger reads `event`, `where` of a condition reads
// `subject`, and `if` reads `trigger`. Every field is always present
// (empty when unknown). Evaluation is cost-limited and fails closed: an
// error is a false condition.
const (
	EventType   = "pc.automations.Event"
	SubjectType = "pc.automations.Subject"
	TriggerType = "pc.automations.Trigger"
)

var (
	stringMap = types.NewMapType(types.StringType, types.StringType)
	schema    = celenv.Schema{
		EventType: {Name: EventType, Fields: map[string]celenv.Field{
			"kind": {Type: types.StringType}, "actor_type": {Type: types.StringType}, "actor_id": {Type: types.StringType},
			"decision": {Type: types.StringType}, "reason": {Type: types.StringType}, "operation": {Type: types.StringType},
			"mode": {Type: types.StringType}, "outcome": {Type: types.StringType}, "environment": {Type: types.StringType},
			"destination_class": {Type: types.StringType}, "occurred_at": {Type: types.TimestampType},
			"subjects": {Type: stringMap}, "attrs": {Type: stringMap},
		}},
		SubjectType: {Name: SubjectType, Fields: map[string]celenv.Field{
			"probe": {Type: types.StringType}, "key": {Type: types.StringType}, "fields": {Type: stringMap},
		}},
		TriggerType: {Name: TriggerType, Fields: map[string]celenv.Field{
			"kind": {Type: types.StringType}, "occurred_at": {Type: types.TimestampType}, "params": {Type: stringMap},
		}},
	}
	envOnce sync.Once
	envs    struct {
		event, subject, trigger *celenv.Env
		err                     error
	}
)

func celEnvs() (event, subject, trigger *celenv.Env, err error) {
	envOnce.Do(func() {
		l := celenv.DefaultLimits
		if envs.event, envs.err = celenv.New(l, schema, celenv.Variable{Name: "event", Type: types.NewObjectType(EventType)}); envs.err != nil {
			return
		}
		if envs.subject, envs.err = celenv.New(l, schema, celenv.Variable{Name: "subject", Type: types.NewObjectType(SubjectType)}); envs.err != nil {
			return
		}
		envs.trigger, envs.err = celenv.New(l, schema, celenv.Variable{Name: "trigger", Type: types.NewObjectType(TriggerType)})
	})
	return envs.event, envs.subject, envs.trigger, envs.err
}

// programs caches compiled expressions by environment and source.
type programs struct {
	mu sync.Mutex
	by map[string]*celenv.Program
}

var compiled = &programs{by: map[string]*celenv.Program{}}

func (p *programs) get(env *celenv.Env, tag, src string) (*celenv.Program, error) {
	key := tag + "\x00" + src
	p.mu.Lock()
	prog, ok := p.by[key]
	p.mu.Unlock()
	if ok {
		return prog, nil
	}
	prog, err := env.Compile(src, types.BoolType)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	if len(p.by) > 4096 {
		p.by = map[string]*celenv.Program{}
	}
	p.by[key] = prog
	p.mu.Unlock()
	return prog, nil
}

func eventRecord(e feed.Event) map[string]any {
	subjects := map[string]string{}
	for _, s := range e.Subjects {
		if _, ok := subjects[string(s.Type)]; !ok {
			subjects[string(s.Type)] = s.ID
		}
	}
	attrs := maps.Clone(e.Attrs)
	if attrs == nil {
		attrs = map[string]string{}
	}
	a := types.DefaultTypeAdapter
	return map[string]any{"event": &celenv.Record{TypeName: EventType, Fields: map[string]ref.Val{
		"kind": types.String(e.Kind), "actor_type": types.String(e.ActorType), "actor_id": types.String(e.ActorID),
		"decision": types.String(e.Decision), "reason": types.String(e.Reason), "operation": types.String(e.Operation),
		"mode": types.String(e.Mode), "outcome": types.String(e.Outcome), "environment": types.String(e.Environment),
		"destination_class": types.String(e.DestinationClass), "occurred_at": types.Timestamp{Time: e.OccurredAt},
		"subjects": a.NativeToValue(subjects), "attrs": a.NativeToValue(attrs),
	}}}
}

// MatchEvent evaluates an event trigger's `where` (true when empty).
func MatchEvent(ctx context.Context, where string, e feed.Event) (bool, error) {
	if where == "" {
		return true, nil
	}
	env, _, _, err := celEnvs()
	if err != nil {
		return false, err
	}
	p, err := compiled.get(env, "event", where)
	if err != nil {
		return false, err
	}
	ok, _, err := p.EvalBool(ctx, eventRecord(e))
	return ok && err == nil, err
}

// MatchSubject evaluates a condition's `where` over a probe subject.
func MatchSubject(ctx context.Context, where string, s ProbeSubject) (bool, error) {
	if where == "" {
		return true, nil
	}
	_, env, _, err := celEnvs()
	if err != nil {
		return false, err
	}
	p, err := compiled.get(env, "subject", where)
	if err != nil {
		return false, err
	}
	fields := maps.Clone(s.Fields)
	if fields == nil {
		fields = map[string]string{}
	}
	ok, _, err := p.EvalBool(ctx, map[string]any{"subject": &celenv.Record{TypeName: SubjectType, Fields: map[string]ref.Val{
		"probe": types.String(s.Probe), "key": types.String(s.Key), "fields": types.DefaultTypeAdapter.NativeToValue(fields),
	}}})
	return ok && err == nil, err
}

// MatchIf evaluates the definition's `if` list over the trigger (D2): every
// expression must be true.
func MatchIf(ctx context.Context, conds []string, kind autodomain.TriggerKind, occurred time.Time, params map[string]autodomain.Value) (bool, error) {
	if len(conds) == 0 {
		return true, nil
	}
	_, _, env, err := celEnvs()
	if err != nil {
		return false, err
	}
	ps := make(map[string]string, len(params))
	for k, v := range params {
		ps[k] = v.Text()
	}
	vars := map[string]any{"trigger": &celenv.Record{TypeName: TriggerType, Fields: map[string]ref.Val{
		"kind": types.String(string(kind)), "occurred_at": types.Timestamp{Time: occurred},
		"params": types.DefaultTypeAdapter.NativeToValue(ps),
	}}}
	for i, c := range conds {
		p, err := compiled.get(env, "trigger", c)
		if err != nil {
			return false, fmt.Errorf("if[%d]: %w", i, err)
		}
		ok, _, err := p.EvalBool(ctx, vars)
		if err != nil {
			return false, fmt.Errorf("if[%d]: %w", i, err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// CompileCheck compiles an expression in the named environment ("event",
// "subject" or "trigger"), for validation.
func CompileCheck(envName, src string) error {
	ev, sub, trg, err := celEnvs()
	if err != nil {
		return err
	}
	env := map[string]*celenv.Env{"event": ev, "subject": sub, "trigger": trg}[envName]
	if env == nil {
		return fmt.Errorf("unknown environment %q", envName)
	}
	_, err = compiled.get(env, envName, src)
	return err
}
