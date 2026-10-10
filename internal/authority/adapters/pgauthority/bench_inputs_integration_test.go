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

// BenchmarkAuthorizeReplayInputs measures what keeping replay inputs adds
// to Authorize (G0 M7 design decision 22): accepted refunds as in
// BenchmarkRefund, every other one through an Authority that records,
// seals and stores its inputs, so drift of the database or the machine
// affects both alike. It reports both p50s and p99s.
//
//	go test -tags integration -run '^$' -bench BenchmarkAuthorizeReplayInputs -benchtime 2000x ./internal/authority/adapters/pgauthority/
func BenchmarkAuthorizeReplayInputs(b *testing.B) {
	for _, workers := range []int{1, 8} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			w := newWorld(b)
			w.auth.PermitTTL = time.Minute
			sealer := w.keepInputs()
			plain, kept := *w.auth, *w.auth
			plain.Inputs, kept.Inputs = nil, sealer
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
			b.ResetTimer()
			for range workers {
				wg.Go(func() {
					for i := int(next.Add(1)) - 1; i < b.N; i = int(next.Add(1)) - 1 {
						auth := &plain
						if i%2 == 1 {
							auth = &kept
						}
						req := w.request(run, ids.NewV7(), charges[i], "1.00")
						start := time.Now()
						r, err := auth.Authorize(ctx, w.gw, req)
						took[i] = time.Since(start)
						if err == nil && r.Permit == "" {
							err = fmt.Errorf("no permit: %s %s", r.Decision, decisive(r))
						}
						if err == nil {
							_, err = auth.BeginDispatch(ctx, w.gw, r.PermitID, r.Epoch, finalize.Outbound{})
						}
						if err == nil {
							_, err = auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Accepted, DispatchMS: -1})
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
			var without, with []time.Duration
			for i, d := range took {
				if i%2 == 1 {
					with = append(with, d)
				} else {
					without = append(without, d)
				}
			}
			ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
			for name, ds := range map[string][]time.Duration{"plain": without, "inputs": with} {
				if len(ds) == 0 {
					continue
				}
				slices.Sort(ds)
				b.ReportMetric(ms(ds[len(ds)/2]), name+"-p50-ms")
				b.ReportMetric(ms(ds[len(ds)*99/100]), name+"-p99-ms")
			}
		})
	}
}
