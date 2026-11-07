// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"slices"
	"testing"

	csdomain "github.com/katocxl/pantherclaw/internal/contentsignals/domain"
)

// TestHR760_RuntimeActionsReportDelegated: a runtime action reports
// DELEGATED, as authzen's, when the agent holds the connection's
// credential or the target enforces; never on a brokered connection (the
// gateway would have dispatched it), and never on mcp or http. Content
// signals scan the runtime channel: it is not among the faces they cannot
// see into.
func TestHR760_RuntimeActionsReportDelegated(t *testing.T) {
	for _, mode := range []string{AccessAgentHeld, AccessTargetEnforced} {
		if !Delegable("runtime", mode) {
			t.Errorf("runtime %s is not delegable", mode)
		}
	}
	for _, c := range [][2]string{{"runtime", "broker"}, {"runtime", "none"}, {"runtime", ""}, {"mcp", AccessAgentHeld}, {"http", AccessAgentHeld}} {
		if Delegable(c[0], c[1]) {
			t.Errorf("%s %s is delegable", c[0], c[1])
		}
	}
	if slices.Contains(csdomain.NotInspectedFaces, "runtime") {
		t.Error("content signals do not scan the runtime channel")
	}
}
