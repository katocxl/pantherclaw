// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// TestD97_SetA2APublicUrlIsGatedLikeUpdateConnection: the public URL change
// needs connection.manage and is a change, so a plan that refuses changes
// refuses it, as it does UpdateConnection.
// Covers: F882
func TestD97_SetA2APublicUrlIsGatedLikeUpdateConnection(t *testing.T) {
	set, update := pantherclawv1connect.ConnectionServiceSetA2APublicUrlProcedure, pantherclawv1connect.ConnectionServiceUpdateConnectionProcedure
	if m6Procedures[set] != "connection.manage" || m6Procedures[set] != m6Procedures[update] {
		t.Fatalf("permission %q, UpdateConnection %q", m6Procedures[set], m6Procedures[update])
	}
	if procedureClass(set) != entitlements.ClassChange || procedureClass(set) != procedureClass(update) {
		t.Fatalf("class %s, UpdateConnection %s", procedureClass(set), procedureClass(update))
	}
	for _, st := range []entitlements.Status{entitlements.StatusLapsed, entitlements.StatusPaused, entitlements.StatusNone} {
		if entitlements.Allows(st, procedureClass(set)) {
			t.Errorf("a %s plan allows the change", st)
		}
	}
	if !entitlements.Allows(entitlements.StatusActive, procedureClass(set)) {
		t.Error("an active plan refuses the change")
	}
}
