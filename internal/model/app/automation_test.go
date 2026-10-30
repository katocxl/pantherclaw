// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"cel.dev/cel-go/cel"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	automationText = "when an incident opens, open a case and tell the owner"
	hostile        = `prod' || true || 'x`

	tellNode = `{"id":"tell","type":"notify","next":"file","gate":null,"wait":null,"open_case":null,"branch":null,"switch":null,"terminal":null,` +
		`"notify":{"to":["OWNER"],"title":"Incident opened","body":""}}`
	fileNode = `{"id":"file","type":"open_case","next":"done","gate":null,"notify":null,"wait":null,"branch":null,"switch":null,"terminal":null,` +
		`"open_case":{"title":"Look into it","questions":["Who is affected?"]}}`
	doneNode = `{"id":"done","type":"terminal","next":"","gate":null,"notify":null,"wait":null,"open_case":null,"branch":null,"switch":null,` +
		`"terminal":{"outcome":"SUCCEEDED","finish_when":[{"step":"file","condition":"CASE_OPENED"}]}}`
	routeNode = `{"id":"route","type":"branch","next":"","gate":null,"notify":null,"wait":null,"open_case":null,"switch":null,"terminal":null,` +
		`"branch":{"conditions":[{"field":"environment","op":"eq","value":"prod"}],"then":"tell","else":"file"}}`
	askNode = `{"id":"ask","type":"gate","next":"tell","notify":null,"wait":null,"open_case":null,"branch":null,"switch":null,"terminal":null,` +
		`"gate":{"roles":["automation_publisher"],"min_approvals":1,"deadline_hours":24,"summary":"Go ahead?"}}`
)

func automationAnswer(nodes ...string) string {
	return `{"name":"incident-case","purpose":"Open a case for each incident.","work_kind":"SECURITY_WORK","schedule":null,` +
		`"event":{"on":"incident.opened"},"nodes":[` + strings.Join(nodes, ",") + `],"ambiguities":[]}`
}

func parsedAutomation(t *testing.T, output string) *autodomain.Definition {
	t.Helper()
	_, raw, err := parseAutomation(automationText, []byte(output), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d, err := autodomain.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Covers: F181
func TestT235_TheAutomationSchemaIsClosedAndOffersNoAuthority(t *testing.T) {
	closed(t, automationSchema())
	raw, err := automationSchema().Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"principal"`, `"ceiling"`, `"platform"`, `"where"`, `"params"`, `"users"`, `"exclude"`, `"inbound"`, `"when"`, `"with"`} {
		if strings.Contains(string(raw), field) {
			t.Errorf("the schema offers %s", field)
		}
	}
	for _, kind := range []string{autodomain.KindLaunchRun, autodomain.KindContain, autodomain.KindRevokeGrant, autodomain.KindPauseLaunches, autodomain.KindDeliver} {
		if strings.Contains(string(raw), `"`+kind+`"`) || slices.Contains(draftableSteps(), kind) {
			t.Errorf("a model can draft %s", kind)
		}
	}
}

// Covers: F181
func TestHR543_ADraftedAutomationIsAV2DefinitionWithDerivedAuthority(t *testing.T) {
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	_, raw, err := parseAutomation(automationText, []byte(automationAnswer(routeNode, askNode, tellNode, fileNode, doneNode)), now)
	if err != nil {
		t.Fatal(err)
	}
	d, err := autodomain.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !d.IsV2() || d.Authority.Principal != autodomain.PrincipalSelf || d.Authority.Ceiling != nil {
		t.Fatalf("definition: %+v", d)
	}
	wantPlatform := []autodomain.PlatformScope{{Step: autodomain.KindNotify, Scopes: []string{"OWNER"}}, {Step: autodomain.KindOpenCase}}
	if len(d.Authority.Platform) != 2 || d.Authority.Platform[0].Step != wantPlatform[0].Step ||
		!slices.Equal(d.Authority.Platform[0].Scopes, wantPlatform[0].Scopes) || d.Authority.Platform[1].Step != wantPlatform[1].Step {
		t.Fatalf("platform: %+v", d.Authority.Platform)
	}
	if got := d.ReviewBy.Time(); !got.Equal(now.Add(reviewAfter)) {
		t.Fatalf("review by %v", got)
	}
	p, ok := d.When.Event.Params["environment"]
	if !ok || p.From != "environment" || p.Pattern == "" {
		t.Fatalf("the guard's field is not declared: %+v", d.When.Event)
	}
	if got := d.Flow().Node("route").Branch.When; got != `trigger.params.environment == 'prod'` {
		t.Fatalf("guard: %s", got)
	}
	if err := engine.CompileGuard(d.Flow().Node("route").Branch.When); err != nil {
		t.Fatal(err)
	}
	for _, trigger := range []struct {
		name, schedule, event string
		kind                  autodomain.TriggerKind
	}{
		{"manual", "null", "null", autodomain.TriggerManual},
		{"schedule", `{"cron":"0 9 * * 1","timezone":"UTC"}`, "null", autodomain.TriggerSchedule},
	} {
		output := strings.Replace(automationAnswer(fileNode, doneNode), `"schedule":null`, `"schedule":`+trigger.schedule, 1)
		output = strings.Replace(output, `"event":{"on":"incident.opened"}`, `"event":`+trigger.event, 1)
		if got := parsedAutomation(t, output).When.Kind(); got != trigger.kind {
			t.Errorf("%s: %s", trigger.name, got)
		}
	}
}

// Covers: F181
func TestHR543_AnythingOutsideTheAutomationSubsetIsRefused(t *testing.T) {
	good := automationAnswer(routeNode, askNode, tellNode, fileNode, doneNode)
	swap := func(from, to string) string {
		if !strings.Contains(good, from) {
			t.Fatalf("%s is not in the answer", from)
		}
		return strings.ReplaceAll(good, from, to)
	}
	refused := map[string]string{
		"not JSON":             `here is your automation`,
		"unknown field":        swap(`"name":`, `"principal":"self","name":`),
		"a custom role":        swap("automation_publisher", "security_lead"),
		"a role with no right": swap("automation_publisher", "viewer"),
		"an unknown event":     swap("incident.opened", "tool.discovered"),
		"template in a title":  swap("Incident opened", "Incident {{params.id}}"),
		"template in a body":   swap(`"body":""`, `"body":"see {{ steps.x.output.y }}"`),
		"template in a case":   swap("Look into it", "Look at }}"),
		"template in a query":  swap("Who is affected?", "{{params.id}}"),
		"template in a gate":   swap("Go ahead?", "{{params.id}}"),
		"three approvals":      swap(`"min_approvals":1`, `"min_approvals":3`),
		"a long deadline":      swap(`"deadline_hours":24`, `"deadline_hours":73`),
		"a person's scope":     swap(`"to":["OWNER"]`, `"to":["user:1"]`),
		"a bad name":           swap("incident-case", "Incident Case"),
		"a dead end":           swap(`"next":"done"`, `"next":"nowhere"`),
		"a bad node id":        swap(`"id":"tell"`, `"id":"Tell Them"`),
		"a repeated id":        swap(`"id":"ask"`, `"id":"tell"`),
		"a step going nowhere": swap(`"next":"tell"`, `"next":""`),
		"a finish on a gate":   swap(`"step":"file"`, `"step":"ask"`),
		"another finish":       swap("CASE_OPENED", "RUN_ENDED"),
		"an unknown outcome":   swap("SUCCEEDED", "WON"),
		"an unknown field":     swap(`"field":"environment"`, `"field":"params.env"`),
		"an unknown op":        swap(`"op":"eq"`, `"op":"gt"`),
		"quotes in a value":    swap(`"value":"prod"`, `"value":"prod' || true || 'x"`),
		"no conditions":        swap(`{"field":"environment","op":"eq","value":"prod"}`, ""),
		"a guard, no event":    strings.Replace(good, `"event":{"on":"incident.opened"}`, `"event":null`, 1),
		"two parts":            swap(`"id":"tell","type":"notify","next":"file","gate":null`, `"id":"tell","type":"notify","next":"file","gate":{"roles":["automation_publisher"],"min_approvals":1,"deadline_hours":1,"summary":""}`),
		"the wrong part":       swap(`"id":"file","type":"open_case"`, `"id":"file","type":"wait"`),
		"a bad cron":           strings.Replace(good, `"schedule":null`, `"schedule":{"cron":"often","timezone":"UTC"}`, 1),
		"no terminal":          automationAnswer(tellNode, strings.Replace(fileNode, `"next":"done"`, `"next":"tell"`, 1)),
		"no steps":             automationAnswer(),
	}
	for name, output := range refused {
		if _, _, err := parseAutomation(automationText, []byte(output), time.Now()); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := parseAutomation("open a case for large incidents", []byte(good), time.Now()); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Errorf("a vague term settled silently: %v", err)
	}
}

// A hostile value stays one literal: the expression compares with exactly that
// text and gains no term.
//
// Covers: F181, F304
func TestT235_AHostileValueStaysAPlainLiteral(t *testing.T) {
	env, err := celenv.New(celenv.DefaultLimits, nil, celenv.Variable{Name: "action", Type: cel.MapType(cel.StringType, cel.DynType)})
	if err != nil {
		t.Fatal(err)
	}
	guards, err := celenv.New(celenv.DefaultLimits, nil, engine.GuardVariables...)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{hostile, `x" || true || "y`, `\' || true`, `size('a') > 0`, "line\nbreak"} {
		policy, ok := testFields.renderPolicy([]policyCondition{{Field: "action.params.reference", Op: "eq", Value: value}})
		if value == "line\nbreak" {
			if ok {
				t.Fatal("a control character reached a policy condition")
			}
		} else {
			if !ok {
				t.Fatalf("%q was refused", value)
			}
			p, err := env.Compile(policy, cel.BoolType)
			if err != nil {
				t.Fatalf("%s: %v", policy, err)
			}
			for param, want := range map[string]bool{value: true, "prod": false, "": false} {
				got, _, err := p.EvalBool(context.Background(), map[string]any{"action": map[string]any{"params": map[string]any{"reference": param}}})
				if err != nil || got != want {
					t.Errorf("%s with %q = %v, %v", policy, param, got, err)
				}
			}
		}
		guard, ok := renderGuard([]guardCondition{{Field: "environment", Op: "eq", Value: value}})
		if !ok {
			t.Fatalf("%q was refused", value)
		}
		p, err := guards.Compile(guard, cel.BoolType)
		if err != nil {
			t.Fatalf("%s: %v", guard, err)
		}
		for param, want := range map[string]bool{value: true, "prod": false} {
			vars := map[string]any{"trigger": map[string]any{"params": map[string]any{"environment": param}}, "steps": map[string]any{}}
			if got, _, err := p.EvalBool(context.Background(), vars); err != nil || got != want {
				t.Errorf("%s with %q = %v, %v", guard, param, got, err)
			}
		}
	}
}

// Covers: F181
func TestHR543_APolicyConditionIsCheckedAgainstItsFieldsType(t *testing.T) {
	good := map[string]policyCondition{
		`true`: {},
		`has(action.params.amount) && action.params.amount > money('100.00', 'USD')`: {Field: "action.params.amount", Op: "gt", Value: "100.00", Currency: "USD"},
		`has(action.params.count) && action.params.count <= 5`:                       {Field: "action.params.count", Op: "le", Value: "5"},
		`has(action.params.live) && action.params.live == true`:                      {Field: "action.params.live", Op: "eq", Value: "true"},
		`has(action.params.tier) && action.params.tier != 'gold'`:                    {Field: "action.params.tier", Op: "ne", Value: "gold"},
		`action.env == 'production'`:                                                 {Field: "action.env", Op: "eq", Value: "production"},
	}
	for want, c := range good {
		cs := []policyCondition{c}
		if c == (policyCondition{}) {
			cs = nil
		}
		if got, ok := testFields.renderPolicy(cs); !ok || got != want {
			t.Errorf("%+v = %s, %v", c, got, ok)
		}
	}
	bad := map[string]policyCondition{
		"unknown field":       {Field: "action.params.secret", Op: "eq", Value: "x"},
		"a free expression":   {Field: "true || action.env", Op: "eq", Value: "x"},
		"not an integer":      {Field: "action.params.count", Op: "eq", Value: "five"},
		"not money":           {Field: "action.params.amount", Op: "gt", Value: "lots", Currency: "USD"},
		"no currency":         {Field: "action.params.amount", Op: "gt", Value: "100.00"},
		"a stray currency":    {Field: "action.params.count", Op: "eq", Value: "5", Currency: "USD"},
		"not a boolean":       {Field: "action.params.live", Op: "eq", Value: "yes"},
		"not in the enum":     {Field: "action.params.tier", Op: "eq", Value: "bronze"},
		"an order on text":    {Field: "action.params.reference", Op: "gt", Value: "a"},
		"an unknown op":       {Field: "action.params.count", Op: "matches", Value: "1"},
		"too long":            {Field: "action.params.reference", Op: "eq", Value: strings.Repeat("x", maxValue+1)},
		"an empty value":      {Field: "action.params.reference", Op: "eq", Value: ""},
		"a control character": {Field: "action.params.reference", Op: "eq", Value: "a\x00b"},
	}
	for name, c := range bad {
		if got, ok := testFields.renderPolicy([]policyCondition{c}); ok {
			t.Errorf("%s rendered %s", name, got)
		}
	}
	if _, ok := testFields.renderPolicy(slices.Repeat([]policyCondition{{Field: "action.env", Op: "eq", Value: "x"}}, maxConditions+1)); ok {
		t.Error("conditions are unbounded")
	}
	rule := strings.Replace(goodRule, `"conditions":[]`, `"conditions":[{"field":"action.params.count","op":"gt","value":"many","currency":""}]`, 1)
	if _, _, err := parsePolicy("forbid refunds", policyAnswer(rule), ids.NewV7(), visibleOps, testFields); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Errorf("a value of the wrong type: %v", err)
	}
	rule = strings.Replace(goodRule, `"constraint":null`, `"constraint":{"kind":"amount_max","param":"internal_tool_arg","max":"1","currency":"USD","values":[]}`, 1)
	if _, _, err := parsePolicy("forbid refunds", policyAnswer(rule), ids.NewV7(), visibleOps, testFields); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Errorf("a parameter that is not offered: %v", err)
	}
}

// Covers: F181
func TestHR542_OnlyComparableBuiltinParamsAreOffered(t *testing.T) {
	pkg := &defs.Package{Definitions: []defs.Definition{
		{Params: map[string]defs.ParamSpec{
			"amount": {Type: defs.TypeMoney}, "note": {Type: defs.TypeText}, "script": {Type: defs.TypeCommand}, "body": {Type: defs.TypeContent},
			"file": {Type: defs.TypePath}, "both": {Type: defs.TypeInteger}, "Bad-Name": {Type: defs.TypeInteger},
		}},
		{Params: map[string]defs.ParamSpec{"both": {Type: defs.TypeIdentifier}, "tier": {Type: defs.TypeEnum, Values: []string{"b", "a"}}}},
		{Params: map[string]defs.ParamSpec{"tier": {Type: defs.TypeEnum, Values: []string{"a", "c"}}}},
	}}
	got := BuiltinParams(pkg)
	if len(got) != 2 || got[0].Name != "amount" || got[1].Name != "tier" || !slices.Equal(got[1].Values, []string{"a", "b", "c"}) {
		t.Fatalf("params: %+v", got)
	}
	if names := fieldsOf(nil).paramNames(); !slices.Equal(names, []string{noParam}) || fieldsOf(nil).hasParam(noParam) {
		t.Fatalf("no params: %v", names)
	}
}
