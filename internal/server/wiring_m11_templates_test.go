// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
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
