// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"reflect"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/billing"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// TestTemplateHandler_PortsAreCoreAndAssurance: CreateFromTemplate creates
// through the automations core the server builds and stores the baseline
// tests through assurance, in one transaction (D96, D103 T1); without that
// core it answers UNAVAILABLE rather than pretend.
func TestTemplateHandler_PortsAreCoreAndAssurance(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	h := templateHandler(apiDeps{}, core)
	d, ok := h.Drafts.(automationDrafts)
	if !ok || d.svc != core.svc {
		t.Fatalf("Drafts = %#v, want core's automations app", h.Drafts)
	}
	if s, ok := h.Tests.(automationTests); !ok || s.svc == nil {
		t.Fatalf("Tests = %#v, want assurance", h.Tests)
	}
	if h := templateHandler(apiDeps{}, nil); h.Drafts != nil {
		t.Fatalf("without core, Drafts = %#v", h.Drafts)
	}
}

// TestTemplateTestsAreAssuranceCases: every template's baseline tests
// convert to assurance cases that assurance accepts: known kinds, states and effects.
func TestTemplateTestsAreAssuranceCases(t *testing.T) {
	for _, tm := range templates.List() {
		doc, cases, err := templates.Render(tm.ID, tm.Example())
		if err != nil {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		ac := assuranceCases(cases)
		if len(ac) != len(cases) || len(ac) == 0 {
			t.Fatalf("%s: %d of %d cases", tm.ID, len(ac), len(cases))
		}
		def, err := autodomain.Parse(doc)
		if err != nil {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		if err := assurance.Check(def, ac); err != nil {
			t.Errorf("%s: assurance refuses the cases: %v", tm.ID, err)
		}
		for i, c := range ac {
			if c.Name != cases[i].Name || string(c.Kind) != cases[i].Kind || len(c.Stubs) != len(cases[i].Stubs) {
				t.Errorf("%s: case %d %+v", tm.ID, i, c)
			}
		}
	}
}

// securityPending are the security-step ports another stream still owes:
// core's resume of what a step paused, govern's fleet cohorts
// (COHORT_BASELINE). Until then those steps fail DEPENDENCY_UNAVAILABLE.
// The list is exact, so a new gap and a filled one both fail the test.
var securityPending = []string{"Intake.Cohorts", "Resumer"}

// TestSecurityStepsAreFullyWired (D108): in both process roles the driver
// builds the security steps from the process's core and the server's
// config, and every step's port is set but the pending ones.
func TestSecurityStepsAreFullyWired(t *testing.T) {
	roles := map[string]func(core *automationsCore){
		RoleAll: func(core *automationsCore) { core.attach(&db.Pool{}, &grantsapp.Service{}, runsapp.New(&db.Pool{})) },
		RoleWorker: func(core *automationsCore) {
			if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), core, nil); err != nil {
				t.Fatal(err)
			}
		},
	}
	for role, attach := range roles {
		t.Run(role, func(t *testing.T) {
			var got []securityStepDeps
			prev := automationSecuritySteps
			automationSecuritySteps = func(d securityStepDeps) autoports.StepRegistry {
				got = append(got, d)
				return securitySteps(d)
			}
			t.Cleanup(func() { automationSecuritySteps = prev })
			core := newAutomationsCore(&db.Pool{}, nil, "")
			if role == RoleAll {
				attach(core)
			}
			if _, err := registerAutomationEngineJobs(nil, jobs.NewRegistry(), core, &Config{}, nil, &billing.Service{}, &napp.Service{}, nil); err != nil {
				t.Fatal(err)
			}
			if role == RoleWorker {
				attach(core)
			}
			if len(got) == 0 {
				t.Fatal("the driver built no security steps")
			}
			if missing := nilPorts(reflect.ValueOf(securityPorts(got[0])), ""); !slices.Equal(missing, securityPending) {
				t.Fatalf("unset ports %v, want exactly %v", missing, securityPending)
			}
		})
	}
}

// nilPorts lists the nil interface and pointer fields of a Deps, nested
// dependency structs included, sorted.
func nilPorts(v reflect.Value, prefix string) []string {
	var out []string
	for i := range v.NumField() {
		f, name := v.Field(i), prefix+v.Type().Field(i).Name
		switch f.Kind() {
		case reflect.Interface, reflect.Pointer:
			if f.IsNil() {
				out = append(out, name)
			}
		case reflect.Struct:
			out = append(out, nilPorts(f, name+".")...)
		case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
			reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.Array, reflect.Chan,
			reflect.Func, reflect.Map, reflect.Slice, reflect.String, reflect.UnsafePointer:
			// values, not ports
		}
	}
	slices.Sort(out)
	return out
}
