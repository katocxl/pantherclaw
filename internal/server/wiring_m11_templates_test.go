// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// TestTemplateHandler_DraftsIsCoresApp: CreateFromTemplate creates
// through the automations core the server builds (D96); without that core
// it stays UNAVAILABLE rather than pretend.
func TestTemplateHandler_DraftsIsCoresApp(t *testing.T) {
	core := newAutomationsCore(nil, nil, "", nil, nil)
	h := templateHandler(apiDeps{}, core)
	d, ok := h.Drafts.(automationDrafts)
	if !ok || d.svc != core.svc {
		t.Fatalf("Drafts = %#v, want core's automations app", h.Drafts)
	}
	if h := templateHandler(apiDeps{}, nil); h.Drafts != nil {
		t.Fatalf("without core, Drafts = %#v", h.Drafts)
	}
}
