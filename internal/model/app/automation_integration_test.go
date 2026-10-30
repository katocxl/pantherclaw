// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	automationText = "open a case for large incidents"
	goodAutomation = `{"name":"incident-case","purpose":"Open a case for each incident.","work_kind":"SECURITY_WORK","schedule":null,` +
		`"event":{"on":"incident.opened"},"nodes":[` +
		`{"id":"file","type":"open_case","next":"done","gate":null,"notify":null,"wait":null,"branch":null,"switch":null,"terminal":null,` +
		`"open_case":{"title":"Look into it","questions":[]}},` +
		`{"id":"done","type":"terminal","next":"","gate":null,"notify":null,"wait":null,"open_case":null,"branch":null,"switch":null,` +
		`"terminal":{"outcome":"SUCCEEDED","finish_when":[{"step":"file","condition":"CASE_OPENED"}]}}],` +
		`"ambiguities":[{"term":"large","proposed_threshold":"100 or more affected agents"}]}`
)

func automating(t *testing.T) *fixture {
	t.Helper()
	f, _ := drafting(t)
	f.svc.Automations = &autoapp.Service{Pool: f.p, Clock: clock.System{}, Editions: f.ed}
	f.provider.resp.Output = []byte(goodAutomation)
	return f
}

func (f *fixture) automationAuthor() context.Context {
	return f.as(td.KindUser, td.RoleAutomationAuthor)
}

// Covers: F181
func TestHR544_ADraftedAutomationLandsAsADraftOriginModel(t *testing.T) {
	f := automating(t)
	got, err := f.svc.DraftAutomation(f.automationAuthor(), automationText)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "incident-case" || got.Automation.IsZero() || got.Version.IsZero() {
		t.Fatalf("draft: %+v", got)
	}
	if s := f.text("SELECT state FROM pc.automation_versions WHERE id = '" + got.Version.String() + "'"); s != "DRAFT" {
		t.Fatalf("version state: %s", s)
	}
	if s := f.text("SELECT state FROM pc.automations WHERE id = '" + got.Automation.String() + "'"); s != "DRAFT" {
		t.Fatalf("automation state: %s", s)
	}
	if s := f.text("SELECT definition->>'apiVersion' FROM pc.automation_versions"); !strings.HasSuffix(s, "/v2") {
		t.Fatalf("format: %s", s)
	}
	if s := f.text("SELECT definition->'authority'->>'principal' FROM pc.automation_versions"); s != "self" {
		t.Fatalf("principal: %s", s)
	}
	if n := f.count("SELECT count(*)::int FROM pc.automation_executions"); n != 0 {
		t.Fatalf("a draft ran: %d", n)
	}
	stored, err := f.svc.GetDraft(f.automationAuthor(), got.Version)
	if err != nil {
		t.Fatal(err)
	}
	want := []app.Ambiguity{{Term: "large", ProposedThreshold: "100 or more affected agents"}}
	if stored.Kind != "AUTOMATION" || stored.Origin != "model" || stored.Call != got.Call || !slices.Equal(stored.Ambiguities, want) {
		t.Fatalf("mark: %+v", stored)
	}
	if !slices.Equal(f.provider.last.Catalog.StepKinds, []string{"gate", "notify", "open_case", "wait"}) || len(f.provider.last.Catalog.OperationGroups) != 0 {
		t.Fatalf("catalog: %+v", f.provider.last.Catalog)
	}
}

// Covers: F181
func TestHR541_DraftingAnAutomationNeedsManageAPersonAndTheSwitchOn(t *testing.T) {
	f := automating(t)
	if _, err := f.svc.DraftAutomation(f.as(td.KindUser, td.RoleViewer), automationText); pcerr.ReasonOf(err) != "PERMISSION_DENIED" {
		t.Fatalf("viewer: %v", err)
	}
	if _, err := f.svc.DraftAutomation(f.as(td.KindServiceAccount, td.RoleAutomationAuthor), automationText); !errors.Is(err, app.ErrHuman) {
		t.Fatalf("service account: %v", err)
	}
	if n := f.provider.calls.Load(); n != 0 {
		t.Fatalf("calls left: %d", n)
	}
	f.exec("UPDATE pc.model_settings SET enabled = false")
	if _, err := f.svc.DraftAutomation(f.automationAuthor(), automationText); !errors.Is(err, app.ErrOff) {
		t.Fatalf("off: %v", err)
	}
}

// Covers: F181
func TestT235_ARefusedAutomationStoresNothing(t *testing.T) {
	f := automating(t)
	for name, output := range map[string]string{
		"a custom role": strings.Replace(goodAutomation, `"gate":null,"notify":null,"wait":null,"branch":null`,
			`"gate":{"roles":["security_lead"],"min_approvals":1,"deadline_hours":1,"summary":""},"notify":null,"wait":null,"branch":null`, 1),
		"a template":       strings.Replace(goodAutomation, "Look into it", "{{params.x}}", 1),
		"an unknown event": strings.Replace(goodAutomation, "incident.opened", "tool.seen", 1),
	} {
		f.provider.resp.Output = []byte(output)
		if _, err := f.svc.DraftAutomation(f.automationAuthor(), automationText); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := f.count("SELECT count(*)::int FROM pc.automations"); n != 0 {
		t.Fatalf("automations stored: %d", n)
	}
	if n := f.count("SELECT count(*)::int FROM pc.model_drafts"); n != 0 {
		t.Fatalf("drafts marked: %d", n)
	}
	f.provider.resp.Output = []byte(goodAutomation)
	if _, err := f.svc.DraftAutomation(f.automationAuthor(), automationText); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.DraftAutomation(f.automationAuthor(), automationText); !errors.Is(err, autoapp.ErrNameTaken) {
		t.Fatalf("a taken name: %v", err)
	}
	if n := f.count("SELECT count(*)::int FROM pc.model_drafts"); n != 1 {
		t.Fatalf("drafts marked: %d", n)
	}
}

// A hostile value reaches the stored rule as one literal, and the rule compiles
// against the definition.
//
// Covers: F181
func TestT235_AHostileConditionValueIsStoredAsALiteral(t *testing.T) {
	f, _ := drafting(t)
	f.svc.Params = []app.Param{{Name: "reference", Type: defs.TypeIdentifier}, {Name: "amount", Type: defs.TypeMoney}}
	f.provider.resp.Output = []byte(strings.Replace(goodPolicy, `"conditions":[]`,
		`"conditions":[{"field":"action.params.reference","op":"eq","value":"x' || true || 'y","currency":""},`+
			`{"field":"action.params.amount","op":"gt","value":"100.00","currency":"USD"}]`, 1))
	if _, err := f.svc.DraftPolicy(f.author(), policyText); err != nil {
		t.Fatal(err)
	}
	bundle := f.text("SELECT convert_from(bundle, 'UTF8') FROM pc.policy_versions")
	if !strings.Contains(bundle, `has(action.params.reference)`) || !strings.Contains(bundle, `x\\' || true || \\'y`) {
		t.Fatalf("bundle: %s", bundle)
	}
}
