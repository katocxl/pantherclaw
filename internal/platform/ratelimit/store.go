// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Store is a Limiter in PostgreSQL (pc.rate_counters, purpose
// rate_limit): every replica counts in the same window (HR-376).
type Store struct {
	pool  *db.Pool
	clock clock.Clock
}

// NewStore returns the shared limiter over pool.
func NewStore(pool *db.Pool) *Store { return &Store{pool: pool, clock: clock.System{}} }

// Errors of Take.
var (
	// ErrScope: a scope that is not a short lowercase name.
	ErrScope = errors.New("ratelimit: invalid scope")
	// ErrKey: an empty key or one over 256 bytes.
	ErrKey = errors.New("ratelimit: invalid key")
	// ErrWindow: a window that is not a whole number of seconds from one
	// second to one hour, or a limit below 1.
	ErrWindow = errors.New("ratelimit: invalid window or limit")
)

var scopePattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// MaxWindow is the longest window; the janitor keeps two hours.
const MaxWindow = time.Hour

// Take implements Limiter: one atomic upsert of the key's current window.
func (s *Store) Take(ctx context.Context, scope, key string, window time.Duration, n, limit int) (Decision, error) {
	switch {
	case !scopePattern.MatchString(scope):
		return Decision{}, ErrScope
	case key == "" || len(key) > 256:
		return Decision{}, ErrKey
	case window < time.Second || window > MaxWindow || window%time.Second != 0 || limit < 1 || limit > math.MaxInt32 || n < 1:
		return Decision{}, ErrWindow
	}
	refused := Decision{RetryAfter: retryAfter(s.clock.Now(), window)}
	if n > limit {
		return refused, nil
	}
	var fits bool
	err := s.pool.InGlobalTx(ctx, db.GlobalRateLimit, func(ctx context.Context, tx db.GlobalTx) error {
		_, err := dbq.New(tx).TakeRateCounter(ctx, dbq.TakeRateCounterParams{
			Scope: scope, Key: key, WindowSeconds: window.Seconds(),
			N: int32(n), MaxCount: int32(limit), //nolint:gosec // G115: 1 ≤ n ≤ limit ≤ MaxInt32, checked above
		})
		if db.IsNoRows(err) {
			return nil
		}
		fits = err == nil
		return err
	})
	if err != nil {
		return Decision{}, fmt.Errorf("ratelimit: %w", err)
	}
	if !fits {
		return refused, nil
	}
	return Decision{Allowed: true}, nil
}

// JanitorInterval is how often old windows are removed.
const JanitorInterval = 10 * time.Minute

// JanitorArgs removes windows that started more than two hours ago.
type JanitorArgs struct{}

// Kind implements river.JobArgs.
func (JanitorArgs) Kind() string { return "ratelimit.janitor" }

// InsertOpts keeps one queued janitor.
func (JanitorArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByState: []rivertype.JobState{
		rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
		rivertype.JobStateRunning, rivertype.JobStateScheduled,
	}}}
}

type janitorWorker struct {
	river.WorkerDefaults[JanitorArgs]
	pool *db.Pool
	log  *slog.Logger
}

func (w *janitorWorker) Work(ctx context.Context, _ *river.Job[JanitorArgs]) error {
	n, err := Clean(ctx, w.pool)
	if err == nil && n > 0 {
		w.log.InfoContext(ctx, "ratelimit.janitor", slog.Int64("windows", n))
	}
	return err
}

// Clean removes windows that started more than two hours ago.
func Clean(ctx context.Context, pool *db.Pool) (int64, error) {
	var n int64
	err := pool.InGlobalTx(ctx, db.GlobalRateLimit, func(ctx context.Context, tx db.GlobalTx) error {
		var err error
		n, err = dbq.New(tx).DeleteOldRateCounters(ctx)
		return err
	})
	return n, err
}

// RegisterJanitor adds the janitor's worker to reg.
func RegisterJanitor(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) error {
	if log == nil {
		log = pclog.Discard()
	}
	return jobs.Register[JanitorArgs](reg, &janitorWorker{pool: pool, log: log})
}

// JanitorPeriodicJobs returns the janitor's schedule.
func JanitorPeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(JanitorInterval),
			func() (river.JobArgs, *river.InsertOpts) { return JanitorArgs{}, nil }, nil),
	}
}
