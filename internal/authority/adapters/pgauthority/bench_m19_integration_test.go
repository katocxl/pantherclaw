// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func percentile(sorted []time.Duration, p int) float64 {
	return float64(sorted[len(sorted)*p/100]) / float64(time.Millisecond)
}

// BenchmarkM19FirstOfPeriod measures Authorize on a budget with no row yet
// (first of its period, so it makes Prepare's transaction) and the next
// refund on the same budget, which finds the row (docs/perf/M19.md). Each
// iteration is one fresh budget; prepare-p50-ms is the median of the paired
// differences.
//
//	go test -tags integration -run '^$' -bench BenchmarkM19FirstOfPeriod -benchtime 200x ./internal/authority/adapters/pgauthority/
func BenchmarkM19FirstOfPeriod(b *testing.B) {
	w := newWorld(b)
	w.auth.PermitTTL = time.Minute
	charges := make([]string, 2*b.N)
	for i := range charges {
		charges[i] = fmt.Sprintf("ch_%d", i)
	}
	w.refundable(charges...)
	first, second, diff := make([]time.Duration, b.N), make([]time.Duration, b.N), make([]time.Duration, b.N)
	timed := func(run ids.UUID, charge string) time.Duration {
		req := w.request(run, ids.NewV7(), charge, "1.00")
		start := time.Now()
		r := w.authorize(req)
		took := time.Since(start)
		if r.Permit == "" {
			b.Fatalf("no permit: %s %s", r.Decision, decisive(r))
		}
		return took
	}
	b.ResetTimer()
	for i := range b.N {
		b.StopTimer()
		run := w.run(w.grant("100").ID, ids.UUID{})
		b.StartTimer()
		first[i] = timed(run, charges[2*i])
		second[i] = timed(run, charges[2*i+1])
		diff[i] = first[i] - second[i]
	}
	b.StopTimer()
	slices.Sort(first)
	slices.Sort(second)
	slices.Sort(diff)
	b.ReportMetric(percentile(first, 50), "first-p50-ms")
	b.ReportMetric(percentile(first, 99), "first-p99-ms")
	b.ReportMetric(percentile(second, 50), "next-p50-ms")
	b.ReportMetric(percentile(second, 99), "next-p99-ms")
	b.ReportMetric(percentile(diff, 50), "prepare-p50-ms")
}

// BenchmarkM19BusyRow measures a refund whose budget row another transaction
// holds, past the 100 ms lock timeout: how often it is allowed and how long
// its answer takes (docs/perf/M19.md).
//
//	go test -tags integration -run '^$' -bench BenchmarkM19BusyRow -benchtime 30x ./internal/authority/adapters/pgauthority/
func BenchmarkM19BusyRow(b *testing.B) {
	for _, hold := range []time.Duration{150 * time.Millisecond, 500 * time.Millisecond} {
		b.Run(fmt.Sprintf("hold=%dms", hold.Milliseconds()), func(b *testing.B) {
			w := newWorld(b)
			w.auth.PermitTTL = time.Minute
			w.auth.Store.(*pgauthority.Store).LockTimeout = 100 * time.Millisecond
			charges := make([]string, b.N+1)
			for i := range charges {
				charges[i] = fmt.Sprintf("ch_%d", i)
			}
			w.refundable(charges...)
			run := w.run(w.grant("100000000").ID, ids.UUID{})
			if r := w.authorize(w.request(run, ids.NewV7(), charges[b.N], "1.00")); r.Permit == "" {
				b.Fatalf("the first refund prepares the row: %s %s", r.Decision, decisive(r))
			}
			ctx := context.Background()
			took := make([]time.Duration, b.N)
			allowed := 0
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				req := w.request(run, ids.NewV7(), charges[i], "1.00")
				release := w.holdBudgetRows()
				b.StartTimer()
				start := time.Now()
				done := make(chan bool, 1)
				go func() {
					r, err := w.auth.Authorize(ctx, w.gw, req)
					took[i] = time.Since(start)
					done <- err == nil && r.Permit != ""
				}()
				time.Sleep(hold)
				release()
				if <-done {
					allowed++
				}
			}
			b.StopTimer()
			slices.Sort(took)
			b.ReportMetric(float64(allowed)/float64(b.N), "allowed-ratio")
			b.ReportMetric(percentile(took, 50), "answer-p50-ms")
			b.ReportMetric(float64(took[b.N-1])/float64(time.Millisecond), "answer-max-ms")
		})
	}
}

// BenchmarkM19Read measures an allowed read of a pii field, which records
// its class on the transaction (M16, HR-430), so the numbers carry the
// read-history write (docs/perf/M19.md).
//
//	go test -tags integration -run '^$' -bench BenchmarkM19Read -benchtime 500x ./internal/authority/adapters/pgauthority/
func BenchmarkM19Read(b *testing.B) {
	w := newWorldWith(b, withPIIRefunds)
	w.auth.PermitTTL = time.Minute
	w.refundable("ch_1")
	run := w.run(w.grant("500.00").ID, ids.UUID{})
	took := make([]time.Duration, b.N)
	b.ResetTimer()
	for i := range b.N {
		start := time.Now()
		r := w.readRefund(w.conn, run)
		took[i] = time.Since(start)
		if r.Permit == "" {
			b.Fatalf("no permit: %s %s", r.Decision, decisive(r))
		}
	}
	b.StopTimer()
	slices.Sort(took)
	b.ReportMetric(percentile(took, 50), "authorize-p50-ms")
	b.ReportMetric(percentile(took, 99), "authorize-p99-ms")
}
