// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

// TestT070_VerificationReadsStopWithTheConnection: verification reads use
// PantherClaw's credential for the connection, so they stop whenever a
// dispatch would. With leases already in hand, a gateway whose containment
// stream went stale, a revoked gateway, a connection the stream announces
// as quarantined, and a connection whose configuration is quarantined or
// retired make no read: the target gets no request and the server gets no
// report, so the task waits and nothing is resolved by default (HR-190,
// HR-183, design decisions 1 and 20).
func TestT070_VerificationReadsStopWithTheConnection(t *testing.T) {
	for name, contain := range map[string]func(*harness){
		"a stale containment stream": func(h *harness) { h.containment.err = control.ErrStale },
		"a revoked gateway":          func(h *harness) { h.containment.err = control.ErrRevoked },
		"a quarantine on the stream": func(h *harness) { h.containment.conns[connID] = "QUARANTINED" },
		"a quarantined configuration": func(h *harness) {
			h.conn.State = "QUARANTINED"
		},
		"a retired connection": func(h *harness) { h.conn.State = "RETIRED" },
	} {
		t.Run(name, func(t *testing.T) {
			sim := payments.New(payments.Faults{}, pclog.Discard())
			var sent atomic.Int32
			h := setup(t, simTarget(sim, &sent))
			ctx := context.Background()
			id := refundAt(t, sim, "ch_1", "pc-txn-1")
			leases := func() []dispatch.Lease {
				return []dispatch.Lease{
					{Connection: connID, Task: "t1", Operation: "payments.refund.get", Request: reference(id)},
					{Connection: connID, Task: "t2", Operation: "payments.refund.list", Request: lookup("ch_1"), Correlate: "pc-txn-1"},
				}
			}
			// Before: both leased reads are made and reported.
			f := &fakeVerifications{leases: leases()}
			h.gw.verifications, h.gw.verifyEvery = f, time.Hour
			h.gw.verifyDue(ctx)
			if len(f.reports) != 2 || sent.Load() == 0 {
				t.Fatalf("before: %d reports, %d requests", len(f.reports), sent.Load())
			}
			before := sent.Load()

			h.containment.mu.Lock()
			contain(h)
			h.containment.mu.Unlock()
			f = &fakeVerifications{leases: leases()}
			h.gw.verifications = f
			h.gw.verifyDue(ctx)
			if len(f.reports) != 0 {
				t.Fatalf("%d reports from reads that should not have been made: %+v", len(f.reports), f.reports)
			}
			for _, l := range leases() {
				if _, err := h.gw.engine.VerifyEffect(ctx, h.conn, l); !errors.Is(err, dispatch.ErrContained) {
					t.Errorf("%s: %v, want ErrContained", l.Operation, err)
				}
			}
			if n := sent.Load() - before; n != 0 {
				t.Fatalf("%d requests reached the target", n)
			}
		})
	}
}
