// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metric names (G0 M13 D30): fixed, with the pc_ prefix.
const (
	MetricRPCDuration      = "pc_rpc_duration_seconds"
	MetricDecisions        = "pc_decisions_total"
	MetricPoolInUse        = "pc_db_pool_in_use"
	MetricPoolIdle         = "pc_db_pool_idle"
	MetricPoolWaits        = "pc_db_pool_waits_total"
	MetricPoolWaitSeconds  = "pc_db_pool_wait_seconds_total"
	MetricJobs             = "pc_river_jobs_total"
	MetricRateLimited      = "pc_rate_limit_refusals_total"
	MetricMaintenanceHold  = "pc_maintenance_hold"
	MetricSpansDropped     = "pc_otlp_spans_dropped_total"
	MetricMetricExportsBad = "pc_otlp_metric_exports_failed_total"
)

// Rate-limit scopes, the fixed values of the scope attribute.
const (
	ScopeSignIn     = "sign_in"            // OAuth, device and browser sign-in endpoints
	ScopeSignup     = "signup"             // self-serve organizations
	ScopeInbound    = "automation_inbound" // automation inbound events
	ScopeAuthZEN    = "authzen"            // AuthZEN evaluations
	ScopeWait       = "wait"               // workload wait streams
	ScopeOpsStream  = "ops_stream"         // the operations live stream
	ScopeSignals    = "signals"            // IdP security event receivers
	ScopeReplay     = "replay"             // decision replays
	ScopeConsoleWeb = "console_web"        // console web routes
)

// meterScope names the instruments' instrumentation scope.
const meterScope = "github.com/katocxl/pantherclaw/internal/platform/telemetry"

type instruments struct {
	rpc         metric.Float64Histogram
	decisions   metric.Int64Counter
	jobs        metric.Int64Counter
	rateLimited metric.Int64Counter
}

var (
	instOnce sync.Once
	inst     instruments
)

// get creates the instruments once on the global meter provider; until
// Setup installs one they record nothing, and afterwards they delegate to
// it.
func get() *instruments {
	instOnce.Do(func() {
		m := otel.Meter(meterScope)
		inst.rpc, _ = m.Float64Histogram(MetricRPCDuration, metric.WithUnit("s"),
			metric.WithDescription("Duration of RPC calls by procedure and code."),
			metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))
		inst.decisions, _ = m.Int64Counter(MetricDecisions, metric.WithDescription("Authority decisions by outcome."))
		inst.jobs, _ = m.Int64Counter(MetricJobs, metric.WithDescription("Background jobs worked, by kind and final state of the attempt."))
		inst.rateLimited, _ = m.Int64Counter(MetricRateLimited, metric.WithDescription("Requests refused by a rate limit, by scope."))
	})
	return &inst
}

// RPC records one RPC call's duration by procedure and code.
func RPC(ctx context.Context, procedure, code string, d time.Duration) {
	get().rpc.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String(KeyProcedure, procedure), attribute.String(KeyCode, code)))
}

// Decision counts one Authority decision by its outcome.
func Decision(ctx context.Context, outcome string) {
	get().decisions.Add(ctx, 1, metric.WithAttributes(attribute.String(KeyOutcome, outcome)))
}

// Job counts one worked job by kind and the state the attempt ended in.
func Job(ctx context.Context, kind, state string) {
	get().jobs.Add(ctx, 1, metric.WithAttributes(attribute.String(KeyKind, kind), attribute.String(KeyState, state)))
}

// RateLimited counts one request refused by the rate limit of scope.
func RateLimited(ctx context.Context, scope string) {
	get().rateLimited.Add(ctx, 1, metric.WithAttributes(attribute.String(KeyScope, scope)))
}

// PoolStats are a connection pool's counters.
type PoolStats struct {
	InUse, Idle int64
	Waits       int64
	WaitTime    time.Duration
}

// Process state the observable instruments read.
var (
	held     atomic.Bool
	poolMu   sync.Mutex
	poolStat func() PoolStats
)

// SetMaintenanceHold sets the maintenance-hold gauge (1 while held).
func SetMaintenanceHold(on bool) { held.Store(on) }

// ObservePool makes the pool gauges read stat (the app pool).
func ObservePool(stat func() PoolStats) {
	poolMu.Lock()
	defer poolMu.Unlock()
	poolStat = stat
}

// registerObservables adds the gauges and the exporter's own counters to m.
func registerObservables(m metric.Meter, spansDropped, metricExportsFailed func() int64) error {
	hold, err := m.Int64ObservableGauge(MetricMaintenanceHold, metric.WithDescription("1 while the operator's maintenance hold is on."))
	if err != nil {
		return err
	}
	inUse, err := m.Int64ObservableGauge(MetricPoolInUse, metric.WithDescription("Database connections in use."))
	if err != nil {
		return err
	}
	idle, err := m.Int64ObservableGauge(MetricPoolIdle, metric.WithDescription("Idle database connections."))
	if err != nil {
		return err
	}
	waits, err := m.Int64ObservableCounter(MetricPoolWaits, metric.WithDescription("Connection acquisitions that had to wait."))
	if err != nil {
		return err
	}
	waitS, err := m.Float64ObservableCounter(MetricPoolWaitSeconds, metric.WithUnit("s"),
		metric.WithDescription("Total time spent waiting for a database connection."))
	if err != nil {
		return err
	}
	dropped, err := m.Int64ObservableCounter(MetricSpansDropped, metric.WithDescription("Spans dropped by a full queue or a failed export."))
	if err != nil {
		return err
	}
	failed, err := m.Int64ObservableCounter(MetricMetricExportsBad, metric.WithDescription("Metric exports that failed."))
	if err != nil {
		return err
	}
	_, err = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		var h int64
		if held.Load() {
			h = 1
		}
		o.ObserveInt64(hold, h)
		poolMu.Lock()
		stat := poolStat
		poolMu.Unlock()
		if stat != nil {
			s := stat()
			o.ObserveInt64(inUse, s.InUse)
			o.ObserveInt64(idle, s.Idle)
			o.ObserveInt64(waits, s.Waits)
			o.ObserveFloat64(waitS, s.WaitTime.Seconds())
		}
		o.ObserveInt64(dropped, spansDropped())
		o.ObserveInt64(failed, metricExportsFailed())
		return nil
	}, hold, inUse, idle, waits, waitS, dropped, failed)
	return err
}
