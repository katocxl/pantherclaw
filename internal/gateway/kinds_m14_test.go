// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"testing"
)

// TestM14KindsDispatchNothing: a postgres or a2a connection without its
// configuration, or of a kind this build has no sender for, is refused
// before the Authority is asked and nothing reaches the target (G0 M14
// D4, D94): kind_config_missing once a sender is registered,
// kind_not_implemented before; an unknown kind is never dispatched.
func TestM14KindsDispatchNothing(t *testing.T) {
	for _, kind := range []string{"postgres", "a2a", "smtp"} {
		h := setup(t, func(h *harness) { h.conn.Kind = kind })
		r := h.post(t, inbound, nil)
		if (r.refusal.Error != "kind_not_implemented" && r.refusal.Error != "kind_config_missing") ||
			h.auth.snap().authorize != 0 || h.target.calls() != 0 {
			t.Errorf("%s: %d %+v, authorize %d, target %d", kind, r.code, r.refusal, h.auth.snap().authorize, h.target.calls())
		}
	}
}
