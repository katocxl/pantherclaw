// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"log/slog"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Decision replay (G0 M7 design decision 11, HR-197, F504–F508). A replay
// reads the evaluation's decision receipt and sealed inputs and runs the
// pipeline on them; the engine holds read ports only and its source reads
// in READ ONLY transactions, so a replay writes nothing and reaches no
// gateway. This use case adds what the RPC needs: the scope check like
// run.read, the restricted input values, and the rate limit.

// ReplaysPerMinute is how many replays one caller may run per minute
// (design decision 11).
const ReplaysPerMinute = 10

// Replay errors.
var (
	ErrReplayRateLimited     = pcerr.New(pcerr.ResourceExhausted, "REPLAY_RATE_LIMITED", "at most 10 replays per minute: try again later")
	ErrEvaluationNotFound    = pcerr.New(pcerr.NotFound, "EVALUATION_NOT_FOUND", "the transaction has no such evaluation")
	ErrPolicyVersionNotFound = pcerr.New(pcerr.NotFound, "POLICY_VERSION_NOT_FOUND", "policy version not found")
	ErrReplayUnavailable     = pcerr.New(pcerr.Unavailable, "REPLAY_UNAVAILABLE", "decision replay is not available on this server")
)

// Withheld input reasons.
const (
	WithheldPermission = "missing permission evidence.read_restricted where the transaction's agent lives"
	WithheldMissing    = "no inputs are stored for this evaluation: decided before inputs were kept, or removed by retention"
	WithheldTruncated  = "the inputs were larger than 32 KiB compressed and only their digest was kept"
	WithheldUnreadable = "the inputs could not be opened"
)

// Replayer is the replay engine (replay.Engine).
type Replayer interface {
	Replay(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, proposed *ids.UUID) (*replay.Outcome, error)
	RecordedInputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (*recording.Recording, error)
}

// replayLimiter counts each caller's replays: in the shared store, so the
// limit holds across replicas (G0 M19 D201), or in memory on clk without a
// database. A counter error is logged and refuses the replay (HR-376).
type replayLimiter struct {
	limiter ratelimit.Limiter
	window  time.Duration
	log     *slog.Logger
}

// scopeReplay is the shared counter's scope of a caller's replays.
const scopeReplay = "evidence.replay"

// WithReplay adds decision replay to the service, limited to
// ReplaysPerMinute per caller (clk nil: the system clock; it counts only
// without a database).
func (s *Service) WithReplay(r Replayer, clk clock.Clock) *Service {
	var l ratelimit.Limiter = ratelimit.NewMemory(clk)
	if s.pool != nil {
		l = ratelimit.NewStore(s.pool)
	}
	s.replay, s.replayLimit = r, &replayLimiter{limiter: l, window: time.Minute, log: slog.Default()}
	return s
}

// WithReplayWindow shortens the replay limit's window (whole seconds, on
// the database's clock); tests only, so they can wait for a window to end.
// Call it after WithReplay.
func (s *Service) WithReplayWindow(d time.Duration) *Service {
	if s.replayLimit != nil && d >= time.Second && d < time.Minute {
		s.replayLimit.window = d.Truncate(time.Second)
	}
	return s
}

// allow counts one replay of c.
func (l *replayLimiter) allow(ctx context.Context, c tenancy.Caller) bool {
	d, err := l.limiter.Take(ctx, scopeReplay, callerKey(c), l.window, 1, ReplaysPerMinute)
	if err != nil {
		l.log.ErrorContext(ctx, "evidence.replay_rate_unavailable", pclog.Err(err))
		return false
	}
	return d.Allowed
}

// ReplayResult is a replay, with the recorded inputs for a caller allowed
// to read them.
type ReplayResult struct {
	Outcome *replay.Outcome
	// Inputs is the recording's JSON; set only when asked for and the caller
	// holds evidence.read_restricted where the transaction's agent lives.
	Inputs []byte
	// InputsWithheld says why Inputs is empty although they were asked for.
	InputsWithheld string
}

// callerKey identifies a caller for the rate limit.
func callerKey(c tenancy.Caller) string {
	return c.Org.String() + "|" + string(c.Principal.Kind) + "|" + c.Principal.ID.String()
}

// ReplayDecision replays evaluation of txn (0: the latest) under its
// recorded policy, or under the stored policy version proposed. It needs
// evidence.read where the transaction's agent lives; another org's
// transaction is not found (T-037). It never writes (HR-197).
func (s *Service) ReplayDecision(ctx context.Context, txn ids.UUID, evaluation int, proposed *ids.UUID, withInputs bool) (ReplayResult, error) {
	c, err := reader(ctx)
	if err != nil {
		return ReplayResult{}, err
	}
	if s.replay == nil {
		return ReplayResult{}, ErrReplayUnavailable
	}
	// Counted between transactions, never inside one (ratelimit.Store).
	if !s.replayLimit.allow(ctx, c) {
		telemetry.RateLimited(ctx, telemetry.ScopeReplay)
		return ReplayResult{}, ErrReplayRateLimited
	}
	var path td.Path
	var latest int32
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		agentID, err := q.TransactionAgent(ctx, c.Org, txn)
		if db.IsNoRows(err) {
			return ErrTxnNotFound
		} else if err != nil {
			return err
		}
		a, err := q.GetAgent(ctx, c.Org, agentID)
		if err != nil {
			return err
		}
		if path, err = agents.PathOf(ctx, q, a); err != nil {
			return err
		}
		latest, err = q.LatestEvaluation(ctx, c.Org, txn)
		return err
	}, db.ReadOnly())
	if err != nil {
		return ReplayResult{}, err
	}
	if err := c.Require(td.PermEvidenceRead, path); err != nil {
		return ReplayResult{}, err
	}
	if evaluation == 0 {
		evaluation = int(latest)
	}
	if evaluation < 1 || evaluation > int(latest) {
		return ReplayResult{}, ErrEvaluationNotFound
	}
	out, err := s.replay.Replay(ctx, c.Org, txn, evaluation, proposed)
	switch {
	case errors.Is(err, replay.ErrNotFound) && proposed != nil:
		return ReplayResult{}, ErrPolicyVersionNotFound
	case errors.Is(err, replay.ErrNotFound):
		return ReplayResult{}, ErrEvaluationNotFound
	case err != nil:
		return ReplayResult{}, pcerr.Wrap(err, pcerr.Internal, "REPLAY_FAILED", "internal error")
	}
	res := ReplayResult{Outcome: out}
	if !withInputs {
		return res, nil
	}
	if !c.Can(td.PermEvidenceReadRestricted, path) {
		res.InputsWithheld = WithheldPermission
		return res, nil
	}
	rec, err := s.replay.RecordedInputs(ctx, c.Org, txn, evaluation)
	switch {
	case errors.Is(err, replay.ErrNotFound):
		res.InputsWithheld = WithheldMissing
	case errors.Is(err, recording.ErrTruncated):
		res.InputsWithheld = WithheldTruncated
	case err != nil:
		res.InputsWithheld = WithheldUnreadable
	default:
		if res.Inputs, err = recording.Encode(rec); err != nil {
			res.Inputs, res.InputsWithheld = nil, WithheldUnreadable
		}
	}
	return res, nil
}
