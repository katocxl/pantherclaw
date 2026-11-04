// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcanthropic_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcanthropic "github.com/katocxl/pantherclaw/packages/pc-anthropic"
)

// TestPackageDeclaresTheModelOperations: the package decodes, every
// operation is a model dispatch on its fixed path with no dedupe key, the
// create and count operations are reversible, never safe to retry and
// reconcile an unknown outcome (G0 M29 D813, D813a), and the mapper maps
// none of them (the gateway's model path builds the action, D812).
//
// Covers: F980, HR-691
func TestPackageDeclaresTheModelOperations(t *testing.T) {
	p, err := manifest.Decode(pcanthropic.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcanthropic.Name || p.Version != pcanthropic.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	want := map[string]struct {
		api, path string
		access    domain.Access
	}{
		"anthropic.messages.create":       {domain.ModelAPIAnthropicMessages, "/messages", domain.AccessWrite},
		"anthropic.messages.count_tokens": {domain.ModelAPIAnthropicCountTokens, "/messages/count_tokens", domain.AccessWrite},
		"anthropic.models.read":           {domain.ModelAPIAnthropicModels, "/models", domain.AccessRead},
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
	if a, err := m.HTTPRequest(context.Background(), tc, "POST", "/messages", "", "application/json",
		[]byte(`{"model":"sim-model","max_tokens":8,"messages":[]}`)); err == nil {
		t.Fatalf("the mapper mapped a model call: %+v", a.Action)
	}
}
