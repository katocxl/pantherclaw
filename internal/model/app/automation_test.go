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
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
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
		`"branch":{"conditions":[{"field":"outcome","op":"eq","value":"OPEN"}],"then":"tell","else":"file"}}`
	askNode = `{"id":"ask","type":"gate","next":"tell","notify":null,"wait":null,"open_case":null,"branch":null,"switch":null,"terminal":null,` +
		`"gate":{"roles":["automation_publisher"],"min_approvals":1,"deadline_hours":24,"summary":"Go ahead?"}}`
)

func automationAnswer(nodes ...string) string {
	return `{"name":"incident-case","purpose":"Open a case for each incident.","work_kind":"SECURITY_WORK","schedule":null,` +
		`"event":{"on":"alert.raised"},"nodes":[` + strings.Join(nodes, ",") + `],"ambiguities":[]}`
}

// guardAnswer is an answer on event on, branching on field and value.
func guardAnswer(on, field, value string) string {
	route := strings.Replace(strings.Replace(routeNode, `"field":"outcome"`, `"field":"`+field+`"`, 1), `"value":"OPEN"`, `"value":"`+value+`"`, 1)
	return strings.Replace(automationAnswer(route, tellNode, fileNode, doneNode), `"on":"alert.raised"`, `"on":"`+on+`"`, 1)
}

func parsedAutomation(t *testing.T, output string) *autodomain.Definition {
	t.Helper()
	_, raw, err := parseAutomation(automationText, []byte(output), time.Now(), visibleOps)
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
	_, raw, err := parseAutomation(automationText, []byte(automationAnswer(routeNode, askNode, tellNode, fileNode, doneNode)), now, visibleOps)
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
	p, ok := d.When.Event.Params["outcome"]
	if !ok || p.From != "outcome" || p.Pattern == "" {
		t.Fatalf("the guard's field is not declared: %+v", d.When.Event)
	}
	if got := d.Flow().Node("route").Branch.When; got != `trigger.params.outcome == 'OPEN'` {
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
		output = strings.Replace(output, `"event":{"on":"alert.raised"}`, `"event":`+trigger.event, 1)
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
		"an unknown event":     swap("alert.raised", "tool.discovered"),
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
		"an unknown field":     swap(`"field":"outcome"`, `"field":"params.env"`),
		"the environment":      swap(`"field":"outcome"`, `"field":"environment"`),
		"a field it lacks":     swap(`"field":"outcome"`, `"field":"decision"`),
		"an unknown op":        swap(`"op":"eq"`, `"op":"gt"`),
		"quotes in a value":    swap(`"value":"OPEN"`, `"value":"prod' || true || 'x"`),
		"no conditions":        swap(`{"field":"outcome","op":"eq","value":"OPEN"}`, ""),
		"a guard, no event":    strings.Replace(good, `"event":{"on":"alert.raised"}`, `"event":null`, 1),
		"two parts":            swap(`"id":"tell","type":"notify","next":"file","gate":null`, `"id":"tell","type":"notify","next":"file","gate":{"roles":["automation_publisher"],"min_approvals":1,"deadline_hours":1,"summary":""}`),
		"the wrong part":       swap(`"id":"file","type":"open_case"`, `"id":"file","type":"wait"`),
		"a bad cron":           strings.Replace(good, `"schedule":null`, `"schedule":{"cron":"often","timezone":"UTC"}`, 1),
		"no terminal":          automationAnswer(tellNode, strings.Replace(fileNode, `"next":"done"`, `"next":"tell"`, 1)),
		"no steps":             automationAnswer(),
	}
	for name, output := range refused {
		if _, _, err := parseAutomation(automationText, []byte(output), time.Now(), visibleOps); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := parseAutomation("open a case for large incidents", []byte(good), time.Now(), visibleOps); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Errorf("a vague term settled silently: %v", err)
	}
}

// An environment's value is an id, so a name in a condition would never match
// and a path gated on production would be skipped (D321).
//
// Covers: F181, F304
func TestHR543_NoConditionCanNameAnEnvironment(t *testing.T) {
	for _, s := range []ports.Schema{automationSchema(), policySchema(testFields)} {
		raw, err := s.Encode()
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"environment"`, `"action.env"`} {
			if strings.Contains(string(raw), field) {
				t.Errorf("the schema offers %s", field)
			}
		}
	}
	if _, ok := testFields["action.env"]; ok {
		t.Error("the environment is a policy field")
	}
	refused := []string{
		"forbid refunds in production", "if prod, wait for approval", "only on Staging", "any environment", "when env is dev", "not in QA",
		"only on prod1", "in preprod", "for nonprod", "on stg", "in the sandbox",
	}
	for _, text := range refused {
		if err := CheckEnvironment(text); !errors.Is(err, ErrEnvironmentCondition) {
			t.Errorf("%q: %v", text, err)
		}
	}
	for _, text := range []string{"forbid refunds", automationText, "products over 100", "developers may approve", "the devil"} {
		if err := CheckEnvironment(text); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
}

// A trigger param is required, so a guard on a field its event lacks would
// refuse every event, and the automation would never start.
//
// Covers: F181
func TestHR543_AGuardReadsOnlyWhatItsEventFills(t *testing.T) {
	for _, on := range slices.Concat(autodomain.Events, triggers.Vocabulary()) {
		fields, ok := eventFields[on]
		if !ok {
			t.Errorf("%s is not in the table", on)
		}
		for f := range fields {
			if !slices.Contains(guardFields, f) {
				t.Errorf("%s fills %s, which is no guard field", on, f)
			}
		}
	}
	for _, c := range [][3]string{
		{"alert.raised", "outcome", "OPEN"},
		{"action.held", "decision", "HOLD"},
		{"action.denied", "operation", "payments.refund.create"},
		{"effect.recorded", "outcome", "CONFIRMED"},
		{"coverage.lost", "actor_type", "system"},
	} {
		if _, _, err := parseAutomation(automationText, []byte(guardAnswer(c[0], c[1], c[2])), time.Now(), visibleOps); err != nil {
			t.Errorf("%v: %v", c, err)
		}
	}
	for _, c := range [][3]string{
		{"incident.opened", "outcome", "OPEN"},
		{"incident.opened", "decision", "HOLD"},
		{"incident.opened", "operation", "payments.refund.create"},
		{"alert.raised", "mode", "MONITOR"},
		{"action.held", "outcome", "OPEN"},
		{"case.closed", "outcome", "CLOSED"},
		{"coverage.lost", "outcome", "PARTIAL"},
	} {
		if _, _, err := parseAutomation(automationText, []byte(guardAnswer(c[0], c[1], c[2])), time.Now(), visibleOps); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%v: %v", c, err)
		}
	}
}

// A value its field never holds never matches: a gate behind it would be
// skipped, and the draft would read right to its reviewer.
//
// Covers: F181
func TestHR543_AGuardValueIsOneItsEventCanHold(t *testing.T) {
	for on, fields := range eventFields {
		for field, values := range fields {
			if field == fieldOperation {
				values = visibleOps
			}
			if len(values) == 0 {
				t.Errorf("%s %s has no value", on, field)
			}
			for _, value := range values {
				if _, _, err := parseAutomation(automationText, []byte(guardAnswer(on, field, value)), time.Now(), visibleOps); err != nil {
					t.Errorf("%s %s %s: %v", on, field, value, err)
				}
				if field != fieldOperation && !strings.Contains(guardValues(), value) {
					t.Errorf("the schema does not list %s", value)
				}
			}
		}
	}
	for _, c := range [][3]string{
		{"action.decided", "decision", "DENIED"},
		{"action.decided", "decision", "denied"},
		{"action.decided", "decision", "BLOCK"},
		{"action.decided", "decision", "HOLD"},
		{"action.denied", "decision", "ALLOW"},
		{"action.decided", "mode", "production"},
		{"action.decided", "mode", "live"},
		{"run.ended", "outcome", "FAILED"},
		{"run.ended", "outcome", "success"},
		{"grant.issued", "outcome", "success"},
		{"approval.expired", "outcome", "denied"},
		{"effect.recorded", "outcome", "success"},
		{"incident.opened", "outcome", "open"},
		{"automation.finished", "outcome", "denied"},
		{"alert.raised", "actor_type", "SYSTEM"},
		{"action.decided", "operation", "not.a.real.op"},
		{"action.decided", "operation", "an.org.own.tool"},
	} {
		if _, _, err := parseAutomation(automationText, []byte(guardAnswer(c[0], c[1], c[2])), time.Now(), visibleOps); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%v: %v", c, err)
		}
	}
	operation := guardAnswer("action.decided", "operation", visibleOps[0])
	if _, _, err := parseAutomation(automationText, []byte(operation), time.Now(), nil); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Errorf("no built-in operations: %v", err)
	}
}

// Text a person reviews shows what it holds. Each of these hides something
// from the person approving it.
//
// Covers: F181, F304
func TestHR543_TextThatDoesNotShowAsWrittenIsRefused(t *testing.T) {
	for _, c := range []rune{
		0x202e, 0x2066, 0x200b, 0x200d, 0xfeff, 0xad, 0x85, 0x2028, 0x2029, 0xe0041, 0x61c,
		0x34f, 0xfe00, 0x180b, 0x3164, 0xffa0, 0x115f, 0x2800, 0xe000, 0x378,
	} {
		s := "pay" + string(c) + "ment"
		if literalText(s, maxPurpose) || shownLine(s) || plainText(s) {
			t.Errorf("U+%04X passes", c)
		}
		good := automationAnswer(tellNode, fileNode, doneNode)
		if _, _, err := parseAutomation(automationText, []byte(strings.Replace(good, "Look into it", s, 1)), time.Now(), visibleOps); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("U+%04X in a case title: %v", c, err)
		}
		rule := strings.Replace(goodRule, "Forbid refunds", s, 1)
		if _, _, err := parsePolicy("forbid refunds", policyAnswer(rule), ids.NewV7(), visibleOps, testFields); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("U+%04X in a summary: %v", c, err)
		}
		ambiguous := `{"rules":[` + goodRule + `],"ambiguities":[{"term":"refunds","proposed_threshold":"` + s + `"}]}`
		if _, _, err := parsePolicy("forbid refunds", []byte(ambiguous), ids.NewV7(), visibleOps, testFields); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("U+%04X in a threshold: %v", c, err)
		}
	}
	emoji := string([]rune{0x26a0, emojiStyle})
	if !literalText("two\nlines", maxPurpose) || !literalText("Überweisung über 100 €", maxPurpose) ||
		!literalText(emoji, maxPurpose) || !shownLine(emoji) || !plainText(emoji) {
		t.Error("plain text was refused")
	}
}

// Covers: F304
func TestHR542_OnlyBuiltInOperationsAreListed(t *testing.T) {
	a := &defs.Package{Definitions: []defs.Definition{{Operation: "tickets.close"}, {Operation: "payments.refund.create"}}}
	b := &defs.Package{Definitions: []defs.Definition{{Operation: "tickets.close"}}}
	if got := BuiltinOperations(a, b); !slices.Equal(got, []string{"payments.refund.create", "tickets.close"}) {
		t.Fatalf("operations: %v", got)
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
		guard, ok := renderGuard([]guardCondition{{Field: "operation", Op: "eq", Value: value}})
		if !ok {
			t.Fatalf("%q was refused", value)
		}
		p, err := guards.Compile(guard, cel.BoolType)
		if err != nil {
			t.Fatalf("%s: %v", guard, err)
		}
		for param, want := range map[string]bool{value: true, "prod": false} {
			vars := map[string]any{"trigger": map[string]any{"params": map[string]any{"operation": param}}, "steps": map[string]any{}}
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
		"the environment":     {Field: "action.env", Op: "eq", Value: "production"},
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
	if _, ok := testFields.renderPolicy(slices.Repeat([]policyCondition{{Field: "action.params.reference", Op: "eq", Value: "x"}}, maxConditions+1)); ok {
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
