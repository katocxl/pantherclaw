// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"encoding/json/jsontext"
	"errors"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

var params = map[string]autodomain.Value{
	"ticket": {Type: autodomain.ParamString, String: "T-42"},
	"amount": {Type: autodomain.ParamDecimal, Decimal: "12.50"},
	"acct":   {Type: autodomain.ParamUUID, String: "0192f000-0000-7000-8000-0000000000aa"},
}

func spec(kind, with string) autodomain.StepSpec {
	return autodomain.StepSpec{ID: "s", Step: kind, With: jsontext.Value(with)}
}

// HR-276: text fields mix text and placeholders; identifier fields take
// exactly one placeholder; nothing outside the templatable fields renders.
func TestHR276_RenderIsTypedAndOnlyInTemplatableFields(t *testing.T) {
	outs := map[string]map[string]string{"launch": {"run_id": "r-1"}}
	w, err := render(spec(autodomain.KindLaunchRun, `{"agent":"0192f000-0000-7000-8000-000000000003",
		"task_ref":"ticket {{params.ticket}} after {{ steps.launch.output.run_id }}",
		"grant":{"accounts":{"ids":["{{params.acct}}"]}}}`), params, outs)
	if err != nil {
		t.Fatal(err)
	}
	lr := w.(*autodomain.LaunchRunWith)
	if lr.TaskRef != "ticket T-42 after r-1" {
		t.Errorf("task_ref %q", lr.TaskRef)
	}
	if ids := lr.Grant.Accounts.IDs; len(ids) != 1 || ids[0] != "0192f000-0000-7000-8000-0000000000aa" {
		t.Errorf("accounts %v", ids)
	}
	for name, with := range map[string]string{
		"concatenated identifier": `{"agent":"0192f000-0000-7000-8000-000000000003","grant":{"accounts":{"ids":["acct-{{params.ticket}}"]}}}`,
		"templated agent":         `{"agent":"{{params.acct}}"}`,
		"unknown parameter":       `{"agent":"0192f000-0000-7000-8000-000000000003","task_ref":"{{params.nope}}"}`,
		"unknown output":          `{"agent":"0192f000-0000-7000-8000-000000000003","task_ref":"{{steps.x.output.y}}"}`,
		"malformed placeholder":   `{"agent":"0192f000-0000-7000-8000-000000000003","task_ref":"{{params.ticket"}`,
		"expression":              `{"agent":"0192f000-0000-7000-8000-000000000003","task_ref":"{{params.ticket + 1}}"}`,
	} {
		if _, err := render(spec(autodomain.KindLaunchRun, with), params, outs); !errors.Is(err, ErrTemplate) {
			t.Errorf("%s: %v, want ErrTemplate", name, err)
		}
	}
	// A gate's summary renders; its approvers never do.
	if _, err := render(spec(autodomain.KindGate, `{"approvers":{"roles":["{{params.ticket}}"]},"deadline":"1h"}`),
		params, outs); !errors.Is(err, ErrTemplate) {
		t.Errorf("gate approvers rendered: %v", err)
	}
	g, err := render(spec(autodomain.KindGate, `{"approvers":{"roles":["approver"]},"deadline":"1h",
		"summary":"Refund {{params.amount}} for {{params.ticket}}"}`), params, outs)
	if err != nil || g.(*autodomain.GateWith).Summary != "Refund 12.50 for T-42" {
		t.Errorf("gate summary %v %v", g, err)
	}
}

// D83: a runner call's input values are JSON text, rendered from typed
// parameters (strings quoted, numbers exact); text around a placeholder is
// refused.
func TestHR276_CallInputsRenderAsTypedJSON(t *testing.T) {
	p := map[string]autodomain.Value{
		"ticket": {Type: autodomain.ParamString, String: `T-"42"`},
		"amount": {Type: autodomain.ParamDecimal, Decimal: "12.50"},
		"count":  {Type: autodomain.ParamInt, Int: 3},
		"dry":    {Type: autodomain.ParamBool, Bool: true},
	}
	w, err := render(spec(autodomain.KindLaunchRun, `{"agent":"0192f000-0000-7000-8000-000000000003",
		"calls":[{"connection":"0192f000-0000-7000-8000-000000000009","face":"MCP","tool":"refund",
		"input":{"ticket":"{{params.ticket}}","amount":"{{params.amount}}","count":"{{params.count}}",
		"dry":"{{params.dry}}","fixed":"\"literal\""}}]}`), p, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := w.(*autodomain.LaunchRunWith).Calls[0].Input
	want := map[string]string{"ticket": `"T-\"42\""`, "amount": "12.50", "count": "3", "dry": "true", "fixed": `"literal"`}
	for k, v := range want {
		if in[k] != v {
			t.Errorf("input %s = %s, want %s", k, in[k], v)
		}
	}
	if _, err := render(spec(autodomain.KindLaunchRun, `{"agent":"0192f000-0000-7000-8000-000000000003",
		"calls":[{"connection":"0192f000-0000-7000-8000-000000000009","face":"MCP","tool":"refund",
		"input":{"note":"ticket {{params.ticket}}"}}]}`), p, nil); !errors.Is(err, ErrTemplate) {
		t.Errorf("mixed input rendered: %v", err)
	}
}
