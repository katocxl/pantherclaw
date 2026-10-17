// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
)

// TestM14_AuthZENMayReportDelegated: the cooperative channels report the
// outcome delegated, the authzen channel among them; a channel the gateway
// dispatches on never does (HR-186, G0 M14 D4).
func TestM14_AuthZENMayReportDelegated(t *testing.T) {
	for ch, want := range map[string]bool{"hook": true, "sdk": true, "authzen": true, "http": false, "mcp": false, "a2a": false, "": false} {
		if finalize.Delegable(ch) != want {
			t.Errorf("%q: %v", ch, !want)
		}
	}
}
