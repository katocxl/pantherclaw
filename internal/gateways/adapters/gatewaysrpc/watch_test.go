// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gatewaysrpc

import (
	"testing"
	"time"

	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR190_EveryContainmentMessageCarriesTheVerificationsHint: snapshots,
// changes and heartbeats all say whether verifications are waiting, and a
// heartbeat still omits connection states (G0 M7 design decision 1).
func TestHR190_EveryContainmentMessageCarriesTheVerificationsHint(t *testing.T) {
	c := gwapp.Containment{
		Epoch: 2, GatewayActive: true, Connections: map[ids.UUID]string{ids.NewV7(): "ACTIVE"}, AsOf: time.Now(),
		VerificationsWaiting: true,
	}
	for _, kind := range []pantherclawv1.ContainmentStateKind{
		pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT,
		pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_CHANGE,
		pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT,
	} {
		m := containmentOf(kind, c)
		heartbeat := kind == pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT
		if !m.GetVerificationsWaiting() || m.GetEpoch() != 2 || (len(m.GetConnections()) == 0) != heartbeat {
			t.Errorf("%s: %v", kind, m)
		}
	}
	c.VerificationsWaiting = false
	if containmentOf(pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT, c).GetVerificationsWaiting() {
		t.Fatal("a hint without waiting verifications")
	}
}
