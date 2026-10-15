// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	stdmaps "maps"
	"slices"
	"strings"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// The rollout sweeper (D12, D13, D31). A periodic dispatcher lists the orgs
// with a rollout to follow through the audited cross-org lister and
// enqueues one unique job per org (HR-054, HR-056: ids only). The job reads
// the org's new decisions after each rollout's cursor and:
//
//   - marks a target ACKNOWLEDGED when a decision for its agent was made
//     under the rollout's version, and FAILED, notifying the agent's owner,
//     when one was made with the published version because the rollout's
//     could not be used (the recording's selection, FALLBACK);
//   - for a rollout in SHADOW, or the SHADOW cohorts of a PILOT, replays
//     the decision with the recorded policy and with the rollout's version,
//     read-only (HR-232), and records the D5 category: the decision path is
//     never touched (HR-233). Without the Team edition no shadow replay
//     runs;
//   - marks a target VERIFIED once every route of its agent for the
//     version's operations is PARTIAL or ENFORCED, and back ACKNOWLEDGED
//     (COVERAGE_LAPSED) when that lapses, while the rollout is open or
//     completed less than 7 days ago.
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
	// defaultLag is how old a receipt must be before the sweeper reads it
	// (D31): its created_at is its transaction's start, so one committed
	// later than that is never read (a recorded limit).
	defaultLag = 2 * time.Minute
)

// Replayer replays recorded evaluations and reads their recordings, with
// read ports only (replay.Engine, HR-197).
type Replayer interface {
	Replay(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int, proposed *ids.UUID) (*replay.Outcome, error)
	RecordedInputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (*recording.Recording, error)
}

var _ Replayer = (*replay.Engine)(nil)

// Receipts reads decision receipts (replay.Source): the sweeper falls back
// to a receipt's decision basis when a decision's recording cannot be read.
type Receipts interface {
	Receipt(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (string, error)
}

// Swept reports one org's sweep.
type Swept struct {
	Evaluations, Replays           int
	Acknowledged, Failed, Verified int
	Lapsed                         int
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
	// Shadow replays need Team (D31); without it the replay budget is
	// spent, and targets are still followed.
	if err := s.team(ctx); err != nil {
		if !errors.Is(err, ErrEdition) {
			s.log().WarnContext(ctx, "policy.rollout: edition unknown, no shadow replay", slog.String("error", err.Error()))
		}
		b.replays = 0
		b.noShadow = true
	}
	for _, r := range due {
		if err := s.sweepRollout(ctx, org, r, &b, &out); err != nil {
			return out, fmt.Errorf("rollout %s: %w", r.ID, err)
		}
	}
	return out, nil
}

type budget struct {
	evaluations, replays int
	noShadow             bool
}

// scope is what a sweep of one rollout reads before it replays.
type scope struct {
	bundle    *pdomain.Bundle
	ref       string // bundle@version
	shadowAll bool
	shadow    map[ids.UUID]bool
	// cursor is where the sweep starts; hadCursor whether its row exists.
	cursor    dbq.GetRolloutCursorRow
	hadCursor bool
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
		v, err := q.GetPolicyVersionBundle(ctx, org, r.VersionID)
		if err != nil {
			return err
		}
		if sc.bundle, err = polpg.Decode(v.Bundle); err != nil {
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
		switch {
		case db.IsNoRows(err):
			sc.cursor, err = dbq.GetRolloutCursorRow{LastCreatedAt: r.CreatedAt}, nil
		case err == nil:
			sc.hadCursor = true
		}
		if err != nil || limit == 0 {
			return err
		}
		sc.decisions, err = q.RolloutDecisionsAfter(ctx, dbq.RolloutDecisionsAfterParams{
			OrgID: org, LagSeconds: s.lag().Seconds(), AfterCreatedAt: sc.cursor.LastCreatedAt, AfterTxn: optional(sc.cursor.LastTxn),
			AfterEvaluation: sc.cursor.LastEvaluation, MaxRows: int32(limit), //nolint:gosec // ≤ 1000
		})
		return err
	}, db.ReadOnly())
	return sc, err
}

// selection is what a decision recorded about the policy it was decided
// under: from its recording, else (logged) from its receipt's decision
// basis, which names the version but not how it was selected.
type selection struct {
	ref, rollout, selected string
	known                  bool
}

func (s *Service) selectionOf(ctx context.Context, org ids.OrgID, d dbq.RolloutDecisionsAfterRow) (selection, error) {
	rec, err := s.Replay.RecordedInputs(ctx, org, d.TransactionID, int(d.Evaluation))
	if err == nil && rec != nil {
		p := rec.Reads.Policy
		if p == nil || p.Err != "" || p.None {
			return selection{known: true}, nil
		}
		return selection{ref: p.Ref, rollout: p.Rollout, selected: p.Selected, known: true}, nil
	}
	if ctx.Err() != nil {
		return selection{}, ctx.Err()
	}
	s.log().WarnContext(ctx, "policy.rollout: recording unreadable, reading the receipt's basis", slog.String("org", org.String()),
		slog.String("transaction", d.TransactionID.String()), slog.Int("evaluation", int(d.Evaluation)), slog.Any("error", err))
	if s.Receipts == nil {
		return selection{}, nil
	}
	jws, rerr := s.Receipts.Receipt(ctx, org, d.TransactionID, int(d.Evaluation))
	if rerr != nil || jws == "" {
		if ctx.Err() != nil {
			return selection{}, ctx.Err()
		}
		return selection{}, nil
	}
	ref, ok := basisPolicy(jws)
	return selection{ref: ref, known: ok}, nil
}

// basisPolicy reads the policy version (id@version) a decision receipt's
// basis names. It reads the receipt's own claims, which the Authority
// signed; the sweeper only marks status from it.
func basisPolicy(jws string) (string, bool) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Basis struct {
			Policy string `json:"policy"`
		} `json:"basis"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Basis.Policy == "" {
		return "", false
	}
	return claims.Basis.Policy, true
}

func (s *Service) sweepRollout(ctx context.Context, org ids.OrgID, r dbq.PcPolicyRollout, b *budget, out *Swept) error {
	limit := b.evaluations
	if s.Replay == nil {
		limit = 0
	}
	sc, err := s.read(ctx, org, r, limit)
	if err != nil {
		return err
	}
	var events []event
	var results []dbq.InsertShadowResultParams
	counts := map[string]int64{} // every shadow evaluation by category
	next := sc.cursor
	for _, d := range sc.decisions {
		sel, err := s.selectionOf(ctx, org, d)
		if err != nil {
			return err
		}
		underVersion := sel.known && sel.ref == sc.ref
		inShadow := !b.noShadow && (r.Stage == StageShadow || r.Stage == StagePilot) && (sc.shadowAll || sc.shadow[d.AgentID]) &&
			!underVersion
		if inShadow && b.replays < 2 {
			break // the next tick continues with this decision
		}
		switch {
		case sel.selected == pipeline.SelectedFallback && sel.rollout == r.ID.String():
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
				counts[res.Category]++
			} else {
				counts[string(replay.Unevaluable)]++
			}
		}
		next.LastCreatedAt, next.LastTxn, next.LastEvaluation = d.CreatedAt, d.TransactionID, d.Evaluation
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
		if err := s.recordShadow(ctx, q, org, r.ID, results, counts, out); err != nil {
			return err
		}
		after, err := s.verify(ctx, tx, r.ID, sc.bundle, sc.cursor.VerifyAfterAgent, out)
		if err != nil {
			return err
		}
		next.VerifyAfterAgent = after
		return s.moveCursor(ctx, q, org, r.ID, sc, next)
	})
}

// moveCursor saves where the next sweep starts, only from the position this
// one read (D31): a concurrent sweep of the same rollout makes this one
// fail and roll back, so nothing is counted twice.
func (s *Service) moveCursor(ctx context.Context, q *dbq.Queries, org ids.OrgID, rollout ids.UUID, sc scope, next dbq.GetRolloutCursorRow) error {
	if next == sc.cursor && sc.hadCursor {
		return nil
	}
	if !sc.hadCursor {
		return q.InsertRolloutCursor(ctx, dbq.InsertRolloutCursorParams{
			OrgID: org, RolloutID: rollout, LastCreatedAt: next.LastCreatedAt, LastTxn: optional(next.LastTxn),
			LastEvaluation: next.LastEvaluation, VerifyAfterAgent: next.VerifyAfterAgent,
		})
	}
	n, err := q.AdvanceRolloutCursor(ctx, dbq.AdvanceRolloutCursorParams{
		LastCreatedAt: next.LastCreatedAt, LastTxn: optional(next.LastTxn), LastEvaluation: next.LastEvaluation, VerifyAfterAgent: next.VerifyAfterAgent,
		OrgID: org, RolloutID: rollout, OldCreatedAt: sc.cursor.LastCreatedAt, OldTxn: optional(sc.cursor.LastTxn),
		OldEvaluation: sc.cursor.LastEvaluation, OldVerifyAfterAgent: sc.cursor.VerifyAfterAgent,
	})
	if err == nil && n != 1 {
		err = db.ErrLostRace
	}
	return err
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
// the agent is decided by the published version: ids and the version only,
// never the agent's name (free text, HR-158).
func (s *Service) notifyFailed(ctx context.Context, tx db.TenantTx, r dbq.PcPolicyRollout, ref string, agent ids.UUID) error {
	if s.Notify == nil {
		return nil
	}
	org := tx.OrgID()
	owner, err := dbq.New(tx).RolloutAgentOwner(ctx, org, agent)
	if err != nil {
		return err
	}
	m := napp.Message{
		Org: org, Type: "policy.rollout_target_failed", Params: map[string]string{"agent": agent.String(), "version": ref},
		DedupeKey: "policy.rollout_target_failed:" + r.ID.String() + ":" + agent.String(),
	}
	if owner != nil {
		m.Personal = []ids.UUID{*owner}
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
		res.Category, res.Limitation = string(replay.Unevaluable), &lim
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
	res.Category = string(replay.Classify(base.Original.Decision, adomain.Decision(decision), base.Original.Reason, reason))
	return res, true, nil
}

// recordShadow writes a tick's shadow results, up to the rollout's bound,
// and one count row per category for every shadow evaluation (insert-only,
// summed on read: D31).
func (s *Service) recordShadow(ctx context.Context, q *dbq.Queries, org ids.OrgID, rollout ids.UUID,
	results []dbq.InsertShadowResultParams, counts map[string]int64, out *Swept,
) error {
	if len(counts) == 0 {
		return nil
	}
	stored, err := q.CountShadowResults(ctx, org, rollout)
	if err != nil {
		return err
	}
	for _, res := range results {
		if stored >= maxShadowResults {
			break
		}
		n, err := q.InsertShadowResult(ctx, res)
		if err != nil {
			return err
		}
		stored += n
	}
	for _, c := range slices.Sorted(stdmaps.Keys(counts)) {
		if err := q.InsertShadowCount(ctx, dbq.InsertShadowCountParams{OrgID: org, RolloutID: rollout, ID: ids.NewV7(), Category: c, N: counts[c]}); err != nil {
			return err
		}
		out.Shadowed += int(counts[c])
	}
	return nil
}

// coverageRank orders coverage states, weakest first.
var coverageRank = []string{"UNKNOWN", "OBSERVE_ONLY", "PARTIAL", "ENFORCED"}

// scopeKey is one route of an agent: a connection and an exact operation.
type scopeKey struct {
	connection ids.UUID
	operation  string
}

// operations are the exact operations of b's non-ANNOTATE rules, prefix
// rules expanded against the org's active definitions (D31).
func operations(b *pdomain.Bundle, active []string) []string {
	var out []string
	for _, r := range b.Rules {
		if r.Kind == pdomain.Annotate {
			continue
		}
		for _, op := range r.Operations {
			if !strings.HasSuffix(op, ".*") {
				out = append(out, op)
			}
		}
		for _, op := range active {
			if r.CoversOperation(op) {
				out = append(out, op)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// verify follows the next targets (a keyset over agent ids, D31) to VERIFIED
// and back: the scopes are the agent's coverage routes (its own and those of
// every agent of a connection) for the version's exact operations, and each
// needs an unexpired PARTIAL or ENFORCED snapshot, a missing one counting as
// UNKNOWN. Without such a route the target stays ACKNOWLEDGED (NO_ROUTES);
// a VERIFIED target whose coverage lapsed is ACKNOWLEDGED again
// (COVERAGE_LAPSED). It returns where the next sweep continues (nil: from
// the start).
func (s *Service) verify(ctx context.Context, tx db.TenantTx, rollout ids.UUID, b *pdomain.Bundle, after *ids.UUID, out *Swept,
) (*ids.UUID, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	targets, err := q.VerifiableRolloutTargets(ctx, dbq.VerifiableRolloutTargetsParams{
		OrgID: org, RolloutID: rollout, AfterAgent: after, MaxRows: maxVerifyPerTick,
	})
	if err != nil || len(targets) == 0 {
		return nil, err
	}
	defs, err := (&defpg.Store{Pool: s.Pool}).ActiveDefinitionsInTx(ctx, tx, org)
	if err != nil {
		return nil, err
	}
	active := make([]string, 0, len(defs))
	for _, d := range defs {
		active = append(active, d.Operation)
	}
	ops := operations(b, active)
	for _, t := range targets {
		if err := s.verifyTarget(ctx, q, org, rollout, ops, t, out); err != nil {
			return nil, err
		}
	}
	if len(targets) < maxVerifyPerTick {
		return nil, nil //nolint:nilnil // every target was seen: start over next time
	}
	last := targets[len(targets)-1].AgentID
	return &last, nil
}

func (s *Service) verifyTarget(ctx context.Context, q *dbq.Queries, org ids.OrgID, rollout ids.UUID, ops []string,
	t dbq.PcPolicyRolloutTarget, out *Swept,
) error {
	agent := t.AgentID
	routes, err := q.AgentRouteScopes(ctx, org, &agent)
	if err != nil {
		return err
	}
	scopes := map[scopeKey]bool{}
	for _, r := range routes {
		for _, op := range ops {
			if r.Operation == nil || *r.Operation == op {
				scopes[scopeKey{r.ConnectionID, op}] = true
			}
		}
	}
	p := dbq.SetRolloutTargetStateParams{
		State: TargetAcknowledged, OrgID: org, RolloutID: rollout, AgentID: t.AgentID, FromStates: []string{t.State},
	}
	var reason string
	if len(scopes) == 0 {
		reason = "NO_ROUTES"
	} else {
		snaps, err := q.LatestAgentCoverage(ctx, org, t.AgentID)
		if err != nil {
			return err
		}
		seen := map[scopeKey]int{}
		for _, sn := range snaps {
			rank := slices.Index(coverageRank, sn.State)
			if sn.Expired {
				rank = 0
			}
			seen[scopeKey{sn.ConnectionID, sn.Operation}] = rank
		}
		weakest := len(coverageRank) - 1
		for k := range scopes {
			weakest = min(weakest, seen[k]) // a missing snapshot is UNKNOWN (0)
		}
		coverage := coverageRank[weakest]
		p.Coverage = &coverage
		switch {
		case coverage == "PARTIAL" || coverage == "ENFORCED":
			p.State = TargetVerified
		case t.State == TargetVerified:
			reason = "COVERAGE_LAPSED"
		default:
			reason = "COVERAGE_" + coverage
		}
	}
	if reason != "" {
		p.Reason = &reason
	}
	if sameTarget(t, p) {
		return nil
	}
	n, err := q.SetRolloutTargetState(ctx, p)
	if err != nil {
		return err
	}
	switch {
	case p.State == TargetVerified && t.State != TargetVerified:
		out.Verified += int(n)
	case p.State != TargetVerified && t.State == TargetVerified:
		out.Lapsed += int(n)
	}
	return nil
}

func sameTarget(t dbq.PcPolicyRolloutTarget, p dbq.SetRolloutTargetStateParams) bool {
	eq := func(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }
	return t.State == p.State && eq(t.Coverage, p.Coverage) && eq(t.Reason, p.Reason)
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
