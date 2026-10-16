// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/protect"
)

// TestM11ProtectWiring (G0 M11 D96): the protect Gate's change requests are
// the core's change ceremony, and the core's change service and the one
// shared automations service both refuse compromised people through the
// same publishers. Promotions stay NOT_YET until the top wires govern.
func TestM11ProtectWiring(t *testing.T) {
	core := newAutomationsCore(nil, nil, "https://pc.example.test", nil, nil)
	p := newM11Protect(apiDeps{})
	protectCore(p, core)
	c, ok := p.gate.Requests.(protect.Ceremony)
	if !ok || c.Changes == nil || c.Changes != core.changes {
		t.Fatalf("the Gate's Requests is %#v, not the core's change ceremony", p.gate.Requests)
	}
	if core.changes.Compromise == nil || core.changes.Compromise != p.publishers {
		t.Fatal("the change service does not refuse compromised people")
	}
	if core.svc.Compromise == nil || core.svc.Compromise != p.publishers {
		t.Fatal("the automations service does not refuse compromised people")
	}
	if p.publishers.Undo[protect.ItemPromotion] == nil {
		t.Fatal("promotion ROLLBACK has no answer")
	}
}
