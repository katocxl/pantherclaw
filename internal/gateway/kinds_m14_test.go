// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"testing"
)

// TestM14KindsDispatchNothing: until the gateway can dispatch it, an a2a
// connection refuses every call before the Authority is asked, and nothing
// reaches the target (G0 M14 D4: fail closed). Postgres has its sender
// (D75); without its configuration it sends nothing either
// (TestHR307_PostgresWithoutConfigurationSendsNothing).
func TestM14KindsDispatchNothing(t *testing.T) {
	for _, kind := range []string{"a2a"} {
		h := setup(t, func(h *harness) { h.conn.Kind = kind })
		r := h.post(t, inbound, nil)
		if r.refusal.Error != "kind_not_implemented" || h.auth.snap().authorize != 0 || h.target.calls() != 0 {
			t.Errorf("%s: %d %+v, authorize %d, target %d", kind, r.code, r.refusal, h.auth.snap().authorize, h.target.calls())
		}
	}
}
