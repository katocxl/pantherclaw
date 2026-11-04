// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcopenai_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcopenai "github.com/katocxl/pantherclaw/packages/pc-openai"
)

// TestPackageDeclaresTheModelOperations: the package decodes, every
// operation is a model dispatch on its fixed path with no dedupe key, the
// create operations are reversible, never safe to retry and reconcile an
// unknown outcome (G0 M29 D813, D813a), only chat has choices (1..16), and
// the mapper maps none of them (the gateway's model path builds the action,
// D812).
//
// Covers: F980, HR-691
func TestPackageDeclaresTheModelOperations(t *testing.T) {
	p, err := manifest.Decode(pcopenai.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcopenai.Name || p.Version != pcopenai.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	want := map[string]struct {
		api, path string
		access    domain.Access
	}{
		"openai.chat.create":      {domain.ModelAPIOpenAIChat, "/chat/completions", domain.AccessWrite},
		"openai.responses.create": {domain.ModelAPIOpenAIResponses, "/responses", domain.AccessWrite},
		"openai.models.read":      {domain.ModelAPIOpenAIModels, "/models", domain.AccessRead},
	}
	if len(p.Definitions) != len(want) {
		t.Fatalf("%d definitions", len(p.Definitions))
	}
	for _, d := range p.Definitions {
		w, ok := want[d.Operation]
		if !ok || !d.IsModel() || d.Dispatch.Model.API != w.api || d.Dispatch.Model.Path != w.path || d.Access != w.access {
			t.Errorf("%s: %+v", d.Operation, d.Dispatch)
			continue
		}
		if len(d.Dedupe) != 0 || d.Reversibility != domain.Reversible || d.Dispatch.CredentialPattern == "" {
			t.Errorf("%s: dedupe %v reversibility %s", d.Operation, d.Dedupe, d.Reversibility)
		}
		if d.Access == domain.AccessWrite && (d.Retry.Safe || d.Retry.OnUnknown != domain.OnUnknownReconcile) {
			t.Errorf("%s: retry %+v", d.Operation, d.Retry)
		}
		c, has := d.Params["choices"]
		if has != (d.Operation == "openai.chat.create") || (has && (c.Min != "1" || c.Max != "16")) {
			t.Errorf("%s: choices %+v", d.Operation, c)
		}
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	tc := mapping.Context{
		Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
		RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
		AgentInstance: "01920000-0000-7000-8000-000000000005",
	}
	if a, err := m.HTTPRequest(context.Background(), tc, "POST", "/chat/completions", "", "application/json",
		[]byte(`{"model":"sim-model","messages":[]}`)); err == nil {
		t.Fatalf("the mapper mapped a model call: %+v", a.Action)
	}
}
