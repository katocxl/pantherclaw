// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// BenchmarkRefund measures accepted refunds through the Authority on
// PostgreSQL, as a gateway makes them: Authorize, BeginDispatch and
// RecordExecution, every refund of one task budget (docs/perf/M4.md). A
// fixed number of workers sends them (closed loop), so the code paths can
// be compared without the open-loop overload of the load driver. It reports
// Authorize's p50 and p99 and the refunds per second.
//
//	go test -tags integration -run '^$' -bench BenchmarkRefund -benchtime 1000x ./internal/authority/adapters/pgauthority/
func BenchmarkRefund(b *testing.B) {
	for _, workers := range []int{1, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			w := newWorld(b)
			w.auth.PermitTTL = time.Minute
			run := w.run(w.grant("100000000").ID, ids.UUID{})
			charges := make([]string, b.N)
			for i := range charges {
				charges[i] = fmt.Sprintf("ch_%d", i)
			}
			w.refundable(charges...)
			ctx := context.Background()
			took := make([]time.Duration, b.N)
			var next atomic.Int64
			var wg sync.WaitGroup
			// The outcomes reach the budget row as the server's sweep job
			// applies them, once a second (ADR-0015).
			stop, settled := make(chan struct{}), make(chan error, 1)
			go func() {
				for {
					select {
					case <-stop:
						settled <- nil
						return
					case <-time.After(time.Second):
					}
					if _, err := w.auth.Store.ApplySettlements(ctx, w.org); err != nil {
						settled <- err
						return
					}
				}
			}()
			b.ResetTimer()
			for range workers {
				wg.Go(func() {
					for i := int(next.Add(1)) - 1; i < b.N; i = int(next.Add(1)) - 1 {
						req := w.request(run, ids.NewV7(), charges[i], "1.00")
						start := time.Now()
						r, err := w.auth.Authorize(ctx, w.gw, req)
						took[i] = time.Since(start)
						if err == nil && r.Permit == "" {
							err = fmt.Errorf("no permit: %s %s", r.Decision, decisive(r))
						}
						if err == nil {
							_, err = w.auth.BeginDispatch(ctx, w.gw, r.PermitID, r.Epoch, finalize.Outbound{})
						}
						if err == nil {
							_, err = w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Accepted, DispatchMS: -1})
						}
						if err != nil {
							b.Error(err)
							return
						}
					}
				})
			}
			wg.Wait()
			b.StopTimer()
			close(stop)
			if err := <-settled; err != nil {
				b.Fatal(err)
			}
			slices.Sort(took)
			ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
			b.ReportMetric(ms(took[b.N/2]), "authorize-p50-ms")
			b.ReportMetric(ms(took[b.N*99/100]), "authorize-p99-ms")
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "refunds/s")
		})
	}
}
