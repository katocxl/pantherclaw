// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The rollout sweeper (D12, D13). A periodic dispatcher lists the orgs with
// a rollout to follow through the audited cross-org lister and enqueues one
// unique job per org (HR-054, HR-056: ids only). The job reads the org's
// new decisions after each rollout's cursor and:
//
//   - marks a target ACKNOWLEDGED when a decision for its agent was made
//     under the rollout's version, and FAILED, notifying the agent's owner,
//     when one was made with the published version because the rollout's
//     could not be used (the recording's selection, FALLBACK);
//   - for a rollout in SHADOW, or the SHADOW cohorts of a PILOT, replays
//     the decision with the recorded policy and with the rollout's version,
//     read-only (HR-232), and records the D5 category: the decision path is
//     never touched (HR-233);
//   - marks an ACKNOWLEDGED target VERIFIED once the latest coverage of its
//     agent for the version's operations is PARTIAL or ENFORCED.
//
// The Authority never writes these rows (HR-233).
const (
	// ListDue is the lister purpose policy_rollouts_due (migration 00111).
	ListDue db.ListerPurpose = "policy_rollouts_due"

	// SweepInterval is how often the dispatcher runs.
	SweepInterval = time.Minute

	maxOrgsPerDispatch = 1000
	// maxEvaluationsPerTick and maxReplaysPerTick bound one org's job; the
	// next tick continues from the cursor.
	maxEvaluationsPerTick = 1000
	maxReplaysPerTick     = 500
	// maxShadowResults bounds a rollout's result rows; past it only the
	// daily counts grow (D13).
	maxShadowResults = 100_000
	maxVerifyPerTick = 200
	sweepTimeout     = 5 * time.Minute
	defaultLag       = time.Minute
)

// Replayer replays recorded evaluations and reads their recordings, with
// read ports only (replay.Engine, HR-197).
type Replayer interface {
	Replay(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, proposed *ids.UUID) (*replay.Outcome, error)
	RecordedInputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (*recording.Recording, error)
}

var _ Replayer = (*replay.Engine)(nil)

// Swept reports one org's sweep.
type Swept struct {
	Evaluations, Replays           int
	Acknowledged, Failed, Verified int
	Shadowed                       int
}

// SweepOrg follows one org's due rollouts (the job's work).
func (s *Service) SweepOrg(ctx context.Context, org ids.OrgID) (Swept, error) {
	var out Swept
	var due []dbq.PcPolicyRollout
	if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		due, err = dbq.New(tx).DuePolicyRollouts(ctx, org)
		return err
	}, db.ReadOnly()); err != nil {
		return out, err
	}
	b := budget{evaluations: maxEvaluationsPerTick, replays: maxReplaysPerTick}
	for _, r := range due {
		if err := s.sweepRollout(ctx, org, r, &b, &out); err != nil {
			return out, fmt.Errorf("rollout %s: %w", r.ID, err)
		}
	}
	return out, nil
}

type budget struct{ evaluations, replays int }

// scope is what a sweep of one rollout reads before it replays.
type scope struct {
	version   dbq.GetPolicyVersionBundleRow
	bundle    *pdomain.Bundle
	ref       string // bundle@version
	shadowAll bool
	shadow    map[ids.UUID]bool
	cursor    dbq.GetRolloutCursorRow
	decisions []dbq.RolloutDecisionsAfterRow
}

// event is what one decision said about a target.
type event struct {
	agent  ids.UUID
	failed bool
}

func (s *Service) lag() time.Duration {
	if s.Lag == 0 {
		return defaultLag
	}
	return max(s.Lag, 0)
}

func (s *Service) read(ctx context.Context, org ids.OrgID, r dbq.PcPolicyRollout, limit int) (scope, error) {
	var sc scope
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if sc.version, err = q.GetPolicyVersionBundle(ctx, org, r.VersionID); err != nil {
			return err
		}
		if sc.bundle, err = polpg.Decode(sc.version.Bundle); err != nil {
			return err
		}
		sc.ref = fmt.Sprintf("%s@%d", sc.bundle.ID, sc.bundle.Version)
		cohorts, err := q.ListPolicyRolloutCohorts(ctx, org, r.ID)
		if err != nil {
			return err
		}
		sc.shadow = map[ids.UUID]bool{}
		sc.shadowAll = r.Stage == StageShadow && len(cohorts) == 0
		for _, c := range cohorts {
			if c.Mode != ModeShadow || (r.Stage != StageShadow && r.Stage != StagePilot) {
				continue
			}
			agents, err := q.ListPolicyCohortMembers(ctx, org, c.CohortID)
			if err != nil {
				return err
			}
			for _, a := range agents {
				sc.shadow[a] = true
			}
		}
		sc.cursor, err = q.GetRolloutCursor(ctx, org, r.ID)
		if db.IsNoRows(err) {
			sc.cursor, err = dbq.GetRolloutCursorRow{LastCreatedAt: r.CreatedAt}, nil
		}
		if err != nil {
			return err
		}
		sc.decisions, err = q.RolloutDecisionsAfter(ctx, dbq.RolloutDecisionsAfterParams{
			OrgID: org, LagSeconds: s.lag().Seconds(), AfterCreatedAt: sc.cursor.LastCreatedAt, AfterTxn: sc.cursor.LastTxn,
			MaxRows: int32(limit), //nolint:gosec // ≤ 1000
		})
		return err
	}, db.ReadOnly())
	return sc, err
}

func (s *Service) sweepRollout(ctx context.Context, org ids.OrgID, r dbq.PcPolicyRollout, b *budget, out *Swept) error {
	var sc scope
	if s.Replay != nil && b.evaluations > 0 {
		var err error
		if sc, err = s.read(ctx, org, r, b.evaluations); err != nil {
			return err
		}
	} else {
		var err error
		if sc, err = s.read(ctx, org, r, 1); err != nil {
			return err
		}
		sc.decisions = nil
	}
	var events []event
	var results []dbq.InsertShadowResultParams
	var uncounted []Category // shadow evaluations whose replay failed: counted, no row
	cursor, moved := sc.cursor, false
	for _, d := range sc.decisions {
		var pol *recording.Policy
		rec, err := s.Replay.RecordedInputs(ctx, org, d.TransactionID, int(d.Evaluation))
		switch {
		case ctx.Err() != nil:
			return ctx.Err()
		case err == nil && rec != nil:
			pol = rec.Reads.Policy
		}
		underVersion := pol != nil && pol.Err == "" && !pol.None && pol.Ref == sc.ref
		inShadow := (r.Stage == StageShadow || r.Stage == StagePilot) && (sc.shadowAll || sc.shadow[d.AgentID]) && !underVersion
		if inShadow && b.replays < 2 {
			break // the next tick continues with this decision
		}
		switch {
		case pol != nil && pol.Selected == pipeline.SelectedFallback && pol.Rollout == r.ID.String():
			events = append(events, event{agent: d.AgentID, failed: true})
		case underVersion:
			events = append(events, event{agent: d.AgentID})
		}
		if inShadow {
			b.replays -= 2
			out.Replays += 2
			res, ok, err := s.shadowOf(ctx, org, r, d)
			if err != nil {
				return err
			}
			if ok {
				results = append(results, res)
			} else {
				uncounted = append(uncounted, Unevaluable)
			}
		}
		cursor, moved = dbq.GetRolloutCursorRow{LastCreatedAt: d.CreatedAt, LastTxn: d.TransactionID}, true
		b.evaluations--
		out.Evaluations++
	}
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		switch r.Stage {
		case StagePilot:
			if _, err := q.AddCohortRolloutTargets(ctx, org, r.ID); err != nil {
				return err
			}
		case StageComplete:
			if _, err := q.AddAllRolloutTargets(ctx, r.ID, org); err != nil {
				return err
			}
		}
		for _, e := range events {
			if err := s.applyEvent(ctx, tx, r, sc, e, out); err != nil {
				return err
			}
		}
		if err := s.recordShadow(ctx, q, org, r.ID, results, uncounted, out); err != nil {
			return err
		}
		if moved {
			if err := q.SetRolloutCursor(ctx, dbq.SetRolloutCursorParams{
				OrgID: org, RolloutID: r.ID, LastCreatedAt: cursor.LastCreatedAt, LastTxn: cursor.LastTxn,
			}); err != nil {
				return err
			}
		}
		return s.verify(ctx, q, org, r.ID, sc.bundle, out)
	})
}

// applyEvent moves a target as one decision says: FAILED (from any state
// but EXCEPTION, notifying the agent's owner once) or ACKNOWLEDGED (from
// CONFIGURED or FAILED). An agent without a target is left alone.
func (s *Service) applyEvent(ctx context.Context, tx db.TenantTx, r dbq.PcPolicyRollout, sc scope, e event, out *Swept) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	if !e.failed {
		n, err := q.SetRolloutTargetState(ctx, dbq.SetRolloutTargetStateParams{
			State: TargetAcknowledged, OrgID: org, RolloutID: r.ID, AgentID: e.agent,
			FromStates: []string{TargetConfigured, TargetFailed},
		})
		out.Acknowledged += int(n)
		return err
	}
	reason := "FALLBACK"
	n, err := q.SetRolloutTargetState(ctx, dbq.SetRolloutTargetStateParams{
		State: TargetFailed, Reason: &reason, OrgID: org, RolloutID: r.ID, AgentID: e.agent,
		FromStates: []string{TargetConfigured, TargetAcknowledged, TargetVerified},
	})
	if err != nil || n == 0 {
		return err
	}
	out.Failed++
	return s.notifyFailed(ctx, tx, r, sc.ref, e.agent)
}

// notifyFailed tells the agent's owner, who resolves the target (F3), that
// the agent is decided by the published version: ids and names only.
func (s *Service) notifyFailed(ctx context.Context, tx db.TenantTx, r dbq.PcPolicyRollout, ref string, agent ids.UUID) error {
	if s.Notify == nil {
		return nil
	}
	org := tx.OrgID()
	a, err := dbq.New(tx).RolloutAgentOwner(ctx, org, agent)
	if err != nil {
		return err
	}
	m := napp.Message{
		Org: org, Type: "policy.rollout_target_failed", Params: map[string]string{"agent": a.Name, "version": ref},
		DedupeKey: "policy.rollout_target_failed:" + r.ID.String() + ":" + agent.String(),
	}
	if a.OwnerUserID != nil {
		m.Personal = []ids.UUID{*a.OwnerUserID}
	}
	_, err = s.Notify.Enqueue(ctx, tx, m)
	return err
}

// shadowOf replays one decision with the recorded policy and with the
// rollout's version (D13). ok is false when the replays themselves could
// not run; the decision then counts as UNEVALUABLE without a row.
func (s *Service) shadowOf(ctx context.Context, org ids.OrgID, r dbq.PcPolicyRollout, d dbq.RolloutDecisionsAfterRow,
) (dbq.InsertShadowResultParams, bool, error) {
	res := dbq.InsertShadowResultParams{
		OrgID: org, RolloutID: r.ID, TransactionID: d.TransactionID, Evaluation: d.Evaluation, AgentID: d.AgentID, Operation: d.Operation,
	}
	base, err := s.Replay.Replay(ctx, org, d.TransactionID, int(d.Evaluation), nil)
	if err != nil {
		if ctx.Err() != nil {
			return res, false, ctx.Err()
		}
		s.log().WarnContext(ctx, "policy.rollout: replay failed", slog.String("org", org.String()),
			slog.String("transaction", d.TransactionID.String()), slog.String("error", err.Error()))
		return res, false, nil
	}
	res.OriginalDecision, res.OriginalReason = string(base.Original.Decision), base.Original.Reason
	if res.OriginalDecision == "" || res.OriginalReason == "" {
		return res, false, nil // the receipt's body was removed: nothing to compare with
	}
	unevaluable := func(lims []replay.Limitation, fallback string) (dbq.InsertShadowResultParams, bool, error) {
		codes := []string{}
		for _, l := range lims {
			if !slices.Contains(codes, l.Code) {
				codes = append(codes, l.Code)
			}
		}
		if len(codes) == 0 {
			codes = append(codes, fallback)
		}
		lim := strings.Join(codes, ",")
		if len(lim) > 500 {
			lim = lim[:500]
		}
		res.Category, res.Limitation = string(Unevaluable), &lim
		return res, true, nil
	}
	if !base.Complete {
		return unevaluable(base.Incomplete, "INCOMPLETE")
	}
	if !base.Reproduced {
		return unevaluable(nil, "NOT_REPRODUCED")
	}
	version := r.VersionID
	sh, err := s.Replay.Replay(ctx, org, d.TransactionID, int(d.Evaluation), &version)
	if err != nil {
		if ctx.Err() != nil {
			return res, false, ctx.Err()
		}
		return unevaluable(nil, "REPLAY_FAILED")
	}
	if !sh.Complete || sh.Decision == "" || sh.Reason == "" {
		return unevaluable(sh.Incomplete, "INCOMPLETE")
	}
	decision, reason := string(sh.Decision), sh.Reason
	res.ShadowDecision, res.ShadowReason = &decision, &reason
	res.Category = string(Classify(base.Original.Decision, adomain.Decision(decision), base.Original.Reason, reason))
	return res, true, nil
}

// recordShadow writes a tick's shadow results, up to the rollout's bound,
// and counts every one by day and category.
func (s *Service) recordShadow(ctx context.Context, q *dbq.Queries, org ids.OrgID, rollout ids.UUID,
	results []dbq.InsertShadowResultParams, uncounted []Category, out *Swept,
) error {
	if len(results) == 0 && len(uncounted) == 0 {
		return nil
	}
	stored, err := q.CountShadowResults(ctx, org, rollout)
	if err != nil {
		return err
	}
	for _, res := range results {
		if stored < maxShadowResults {
			n, err := q.InsertShadowResult(ctx, res)
			if err != nil {
				return err
			}
			if n == 0 {
				continue // recorded by an earlier tick that did not move the cursor
			}
			stored += n
		}
		if err := q.AddShadowCount(ctx, org, rollout, res.Category); err != nil {
			return err
		}
		out.Shadowed++
	}
	for _, c := range uncounted {
		if err := q.AddShadowCount(ctx, org, rollout, string(c)); err != nil {
			return err
		}
		out.Shadowed++
	}
	return nil
}

// coverageRank orders coverage states, weakest first.
var coverageRank = []string{"UNKNOWN", "OBSERVE_ONLY", "PARTIAL", "ENFORCED"}

// verify marks ACKNOWLEDGED targets VERIFIED when the latest unexpired
// coverage snapshots of their agent for the version's rule operations are
// all PARTIAL or ENFORCED, keeping the weakest. Without a snapshot a target
// stays ACKNOWLEDGED with the reason COVERAGE_UNKNOWN; with a weaker one,
// COVERAGE_ and the state.
func (s *Service) verify(ctx context.Context, q *dbq.Queries, org ids.OrgID, rollout ids.UUID, b *pdomain.Bundle, out *Swept) error {
	targets, err := q.AcknowledgedRolloutTargets(ctx, org, rollout, maxVerifyPerTick)
	if err != nil {
		return err
	}
	for _, t := range targets {
		snaps, err := q.LatestAgentCoverage(ctx, org, t.AgentID)
		if err != nil {
			return err
		}
		weakest := -1
		for _, sn := range snaps {
			if !governs(b, sn.Operation) {
				continue
			}
			rank := slices.Index(coverageRank, sn.State)
			if sn.Expired {
				rank = 0
			}
			if weakest < 0 || rank < weakest {
				weakest = rank
			}
		}
		p := dbq.SetRolloutTargetStateParams{
			State: TargetAcknowledged, OrgID: org, RolloutID: rollout, AgentID: t.AgentID, FromStates: []string{TargetAcknowledged},
		}
		reason := "COVERAGE_UNKNOWN"
		if weakest >= 0 {
			coverage := coverageRank[max(weakest, 0)]
			p.Coverage = &coverage
			reason = "COVERAGE_" + coverage
			if coverage == "PARTIAL" || coverage == "ENFORCED" {
				p.State, reason = TargetVerified, ""
			}
		}
		if reason != "" {
			p.Reason = &reason
		}
		if sameTarget(t, p) {
			continue
		}
		n, err := q.SetRolloutTargetState(ctx, p)
		if err != nil {
			return err
		}
		if p.State == TargetVerified {
			out.Verified += int(n)
		}
	}
	return nil
}

func sameTarget(t dbq.PcPolicyRolloutTarget, p dbq.SetRolloutTargetStateParams) bool {
	eq := func(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
	return t.State == p.State && eq(t.Coverage, p.Coverage) && eq(t.Reason, p.Reason)
}

// governs reports whether a rule of b that is not ANNOTATE covers
// operation.
func governs(b *pdomain.Bundle, operation string) bool {
	return slices.ContainsFunc(b.Rules, func(r pdomain.Rule) bool {
		return r.Kind != pdomain.Annotate && r.CoversOperation(operation)
	})
}

// SweepOrgArgs asks for one org's sweep.
type SweepOrgArgs struct {
	Org ids.OrgID `json:"org"`
}

// Kind implements river.JobArgs.
func (SweepOrgArgs) Kind() string { return "policy.rollout_sweep_org" }

// InsertOpts keeps one job per org queued at a time.
func (SweepOrgArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{
		ByArgs: true,
		ByState: []rivertype.JobState{
			rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable,
			rivertype.JobStateRunning, rivertype.JobStateScheduled,
		},
	}}
}

// SweepDispatchArgs asks for the orgs to sweep.
type SweepDispatchArgs struct{}

// Kind implements river.JobArgs.
func (SweepDispatchArgs) Kind() string { return "policy.rollout_sweep_dispatch" }

type sweepWorker struct {
	river.WorkerDefaults[SweepOrgArgs]
	svc *Service
}

func (w *sweepWorker) Timeout(*river.Job[SweepOrgArgs]) time.Duration { return sweepTimeout }

func (w *sweepWorker) Work(ctx context.Context, job *river.Job[SweepOrgArgs]) error {
	_, err := w.svc.SweepOrg(ctx, job.Args.Org)
	return err
}

type dispatcher struct {
	river.WorkerDefaults[SweepDispatchArgs]
	pool *db.Pool
}

func (w *dispatcher) Work(ctx context.Context, _ *river.Job[SweepDispatchArgs]) error {
	refs, err := w.pool.CrossOrgList(ctx, ListDue, maxOrgsPerDispatch)
	if err != nil || len(refs) == 0 {
		return err
	}
	client, err := river.ClientFromContextSafely[jobs.TxType](ctx)
	if err != nil {
		return fmt.Errorf("policy rollout: %w", err)
	}
	params := make([]river.InsertManyParams, 0, len(refs))
	for _, r := range refs {
		params = append(params, river.InsertManyParams{Args: SweepOrgArgs{Org: r.Org}})
	}
	if _, err := client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("policy rollout: enqueue: %w", err)
	}
	return nil
}

// Register adds the sweeper's workers to reg.
func Register(reg *jobs.Registry, svc *Service) error {
	if err := jobs.Register[SweepOrgArgs](reg, &sweepWorker{svc: svc}); err != nil {
		return err
	}
	return jobs.Register[SweepDispatchArgs](reg, &dispatcher{pool: svc.Pool})
}

// PeriodicJobs returns the dispatcher's schedule: every minute (D12).
func PeriodicJobs() []*river.PeriodicJob {
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(SweepInterval),
			func() (river.JobArgs, *river.InsertOpts) { return SweepDispatchArgs{}, nil },
			&river.PeriodicJobOpts{RunOnStart: true}),
	}
}
