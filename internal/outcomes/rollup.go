// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outcomes

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Dimensions of the change-assurance metrics (M5).
const (
	DimensionPolicy     = "policy"
	DimensionAutomation = "automation"
)

// Entitlements reads the org's licence.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

func entitled(ctx context.Context, e Entitlements) (bool, error) {
	if e == nil {
		return false, nil
	}
	ent, err := e.Current(ctx)
	if err != nil {
		return false, err
	}
	return ent.OutcomeMetrics(), nil
}

// Rollup writes one org's nightly samples.
type Rollup struct {
	Pool     *db.Pool
	Ents     Entitlements
	Failures reflexports.FailureSink
}

// Run samples every metric for the windows ending at the last UTC midnight,
// once. An org's first run starts its collection, so a window that begins
// earlier is not collected (no backfill). A lapsed edition stops quietly and
// records one owned failure while it is open.
func (r *Rollup) Run(ctx context.Context, org ids.OrgID) (int, error) {
	ok, err := entitled(ctx, r.Ents)
	if err != nil {
		return 0, err
	}
	written := 0
	err = r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if !ok {
			return r.lapsed(ctx, tx, org)
		}
		now, err := q.OpsDBNow(ctx)
		if err != nil {
			return err
		}
		end := now.UTC().Truncate(24 * time.Hour)
		if err := q.StartOutcomeCollection(ctx, org); err != nil {
			return err
		}
		started, err := q.OutcomeCollectionStarted(ctx, org)
		if err != nil {
			return err
		}
		done, err := q.OutcomeSampledFor(ctx, org, end)
		if err != nil || done {
			return err
		}
		if _, err := q.RecordEnrolledMilestones(ctx, org, started); err != nil {
			return err
		}
		if _, err := q.RecordFirstEnforcedMilestones(ctx, org); err != nil {
			return err
		}
		for _, days := range Windows {
			ss, err := sampleWindow(ctx, q, org, started, windowOf(end, days))
			if err != nil {
				return err
			}
			n, err := insert(ctx, q, org, ss)
			if err != nil {
				return err
			}
			written += n
		}
		return nil
	})
	return written, err
}

func (r *Rollup) lapsed(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	// Only an org that once collected has something to lose.
	_, err := dbq.New(tx).OutcomeCollectionStarted(ctx, org)
	if db.IsNoRows(err) || r.Failures == nil {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = r.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: org, Kind: "outcomes.edition_lapsed", DedupeKey: "outcomes.edition_lapsed",
		Summary:  "Outcome metrics stopped: the edition no longer includes them. Earlier samples are kept.",
		NextStep: "Renew a Business or higher licence to resume the nightly rollup.",
		Deadline: time.Now().Add(7 * 24 * time.Hour),
	})
	return err
}

// sampleWindow is every metric's sample for w. A window that began before
// collection started is not collected, whatever the records say.
func sampleWindow(ctx context.Context, q *dbq.Queries, org ids.OrgID, started time.Time, w Window) ([]Sample, error) {
	if w.Start.Before(started) {
		out := make([]Sample, 0, len(Definitions))
		for _, d := range Definitions {
			out = append(out, notCollected(d.Name, "", w, ReasonCollectionNotStarted))
		}
		return out, nil
	}
	var out []Sample
	for _, f := range []func(context.Context, *dbq.Queries, ids.OrgID, time.Time, Window) ([]Sample, error){
		protectedWork, explanation, containment, friction, assurance, automation,
	} {
		ss, err := f(ctx, q, org, started, w)
		if err != nil {
			return nil, err
		}
		out = append(out, ss...)
	}
	return out, nil
}

func insert(ctx context.Context, q *dbq.Queries, org ids.OrgID, ss []Sample) (int, error) {
	written := 0
	for _, s := range ss {
		s = s.finish()
		reasons, err := json.Marshal(s.Reasons)
		if err != nil {
			return 0, err
		}
		n, err := q.InsertOutcomeSample(ctx, dbq.InsertOutcomeSampleParams{
			OrgID: org, ID: ids.NewV7(), Metric: s.Metric, Dimension: s.Dimension, WindowStart: s.Window.Start, WindowEnd: s.Window.End,
			P50Seconds: float8(s.P50), P90Seconds: float8(s.P90), Share: float8(s.Share), Measured: s.Measured, Unmeasured: s.Unmeasured,
			Reasons: reasons, Collected: s.Collected(),
		})
		if err != nil {
			return 0, err
		}
		written += int(n)
	}
	return written, nil
}

func float8(v *float64) pgtype.Float8 {
	if v == nil {
		return pgtype.Float8{}
	}
	return pgtype.Float8{Float64: *v, Valid: true}
}

// protectedWork is M1.
func protectedWork(ctx context.Context, q *dbq.Queries, org ids.OrgID, started time.Time, w Window) ([]Sample, error) {
	rows, err := q.OutcomeAgentJourneys(ctx, org)
	if err != nil {
		return nil, err
	}
	cases := make([]JourneyCase, 0, len(rows))
	for _, r := range rows {
		cases = append(cases, JourneyCase{Enrolled: r.EnrolledAt, Enforced: r.EnforcedAt, Observed: r.Observed})
	}
	before, err := q.OutcomeAgentsBeforeTracking(ctx, org, started)
	if err != nil {
		return nil, err
	}
	seconds, reasons := journeys(w, cases)
	reasons = append(reasons, Reason{Code: ReasonEnrolledBeforeTracking, Count: before})
	return []Sample{duration(MetricProtectedWorkTime, w, seconds, reasons)}, nil
}

// explanation is M2.
func explanation(ctx context.Context, q *dbq.Queries, org ids.OrgID, _ time.Time, w Window) ([]Sample, error) {
	d, err := q.OutcomeExplanationDelivery(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	seconds, err := q.OutcomeExplanationSeconds(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	unread, err := q.OutcomeExplanationUnread(ctx, w.End, org, w.Start)
	if err != nil {
		return nil, err
	}
	return []Sample{
		share(MetricExplanationShare, "", w, d.Delivered, d.Decisions, nil),
		duration(MetricExplanationTime, w, seconds, []Reason{reasonWith(ReasonUnread, unread.N, unread.OldestAgeSeconds)}),
	}, nil
}

// containment is M3. Requested and confirmed stay apart (HR-538).
func containment(ctx context.Context, q *dbq.Queries, org ids.OrgID, _ time.Time, w Window) ([]Sample, error) {
	rows, err := q.OutcomeContainmentEpisodes(ctx, org)
	if err != nil {
		return nil, err
	}
	all := make([]Episode, 0, len(rows))
	for _, r := range rows {
		e := Episode{
			Started: r.StartedAt, OpenRequests: r.OpenRequests, Failed: r.Failed, Declared: r.Declared,
			NoContainmentNeeded: r.NoContainmentNeeded, Ended: r.Ended,
		}
		if r.Confirmed {
			at := r.ConfirmedAt
			e.Confirmed = &at
		}
		all = append(all, e)
	}
	seconds, reasons := episodes(w, all)
	unlinked, err := q.OutcomeGrantRevokesUnlinked(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	reasons = append(reasons, Reason{Code: ReasonGrantRevokeNotLinked, Count: unlinked})

	confirmed, err := q.OutcomeRequestedToConfirmed(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	pending, err := q.OutcomeActionsNotConfirmed(ctx, w.End, org, w.Start)
	if err != nil {
		return nil, err
	}
	var unconfirmed []Reason
	for _, p := range pending {
		code := ReasonRequestedNotConfirmed
		if p.Status == "FAILED" || p.Status == "UNSUPPORTED" {
			code = ReasonFailedOrUnsupported
		}
		unconfirmed = merge(unconfirmed, reasonWith(code, p.N, p.OldestAgeSeconds))
	}
	return []Sample{
		duration(MetricContainmentTime, w, seconds, reasons),
		duration(MetricRequestedToConfirm, w, confirmed, unconfirmed),
	}, nil
}

// merge adds r to reasons, joining a reason of the same code.
func merge(reasons []Reason, r Reason) []Reason {
	for i := range reasons {
		if reasons[i].Code != r.Code {
			continue
		}
		reasons[i].Count += r.Count
		if *r.OldestAgeSeconds > *reasons[i].OldestAgeSeconds {
			reasons[i].OldestAgeSeconds = r.OldestAgeSeconds
		}
		return reasons
	}
	return append(reasons, r)
}

// friction is M4.
func friction(ctx context.Context, q *dbq.Queries, org ids.OrgID, _ time.Time, w Window) ([]Sample, error) {
	waits, err := q.OutcomeApprovalWaits(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	undecided, err := q.OutcomeApprovalsUndecided(ctx, w.End, org, w.Start)
	if err != nil {
		return nil, err
	}
	var open []Reason
	for _, u := range undecided {
		code := ReasonOpenWaiting
		if u.Ended {
			code = ReasonEndedUndecided
		}
		open = append(open, reasonWith(code, u.N, u.OldestAgeSeconds))
	}
	holds, err := q.OutcomeHolds(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	over, err := q.OutcomeOverrides(ctx, dbq.OutcomeOverridesParams{
		OrgID: org, StartAt: w.Start, EndAt: w.End, SettledBefore: w.End.AddDate(0, 0, -7),
	})
	if err != nil {
		return nil, err
	}
	return []Sample{
		duration(MetricApprovalWait, w, waits, open),
		share(MetricHoldShare, "", w, holds.Held, holds.Decisions, nil),
		share(MetricOverrideShare, "", w, over.Overridden, over.Denies, []Reason{{Code: ReasonFollowUpRunning, Count: over.Following}}),
	}, nil
}

// assurance is M5: each check apart, never one score.
func assurance(ctx context.Context, q *dbq.Queries, org ids.OrgID, _ time.Time, w Window) ([]Sample, error) {
	emergency, err := q.OutcomeEmergencyChanges(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	reasons := func(extra ...Reason) []Reason {
		return append(extra, Reason{Code: ReasonEmergencyChange, Count: emergency})
	}

	policies, err := q.OutcomePolicyChecks(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	var validated, tested, simulated, staged, noHistory int64
	for _, v := range policies {
		validated += one(v.Validated)
		tested += one(v.Tested)
		simulated += one(v.Simulated)
		staged += one(v.Staged)
		noHistory += one(v.HistoryMissing)
	}
	n := int64(len(policies))
	out := []Sample{
		share(MetricValidatedShare, DimensionPolicy, w, validated, n, reasons()),
		share(MetricTestedShare, DimensionPolicy, w, tested, n, reasons()),
		share(MetricSimulatedShare, DimensionPolicy, w, simulated, n, reasons()),
		share(MetricStagedShare, DimensionPolicy, w, staged, n, reasons(Reason{Code: ReasonStageHistoryMissing, Count: noHistory})),
	}

	autos, err := q.OutcomeAutomationChecks(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	validated, tested, simulated = 0, 0, 0
	for _, v := range autos {
		validated += one(v.Validated)
		tested += one(v.Tested)
		simulated += one(v.Simulated)
	}
	n = int64(len(autos))
	out = append(out,
		share(MetricValidatedShare, DimensionAutomation, w, validated, n, reasons()),
		share(MetricTestedShare, DimensionAutomation, w, tested, n, reasons()),
		share(MetricSimulatedShare, DimensionAutomation, w, simulated, n, reasons()),
		notCollected(MetricStagedShare, DimensionAutomation, w, ReasonRolloutHistoryUnknown),
	)

	targets, err := q.OutcomeRolloutTargets(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	return append(out, share(MetricFailedTargetShare, DimensionPolicy, w, targets.Failed, targets.Targets, nil)), nil
}

func one(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// automation is M6, per automation. Every ended state has its own share.
func automation(ctx context.Context, q *dbq.Queries, org ids.OrgID, _ time.Time, w Window) ([]Sample, error) {
	rates, err := q.OutcomeAutomationRates(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	if len(rates) == 0 {
		var out []Sample
		for _, d := range Definitions {
			if d.Group == "M6" {
				out = append(out, notCollected(d.Name, "", w, ReasonNoMeasurableCase))
			}
		}
		return out, nil
	}
	rows, err := q.MetricAutomationOutcomes(ctx, org, w.Start, w.End)
	if err != nil {
		return nil, err
	}
	type key struct {
		automation ids.UUID
		outcome    string
	}
	ended := map[key]int64{}
	for _, r := range rows {
		ended[key{r.AutomationID, r.Outcome}] = r.N
	}
	var out []Sample
	for _, r := range rates {
		dim := r.AutomationID.String()
		for outcome, metric := range map[string]string{
			operations.OutcomeCompleted: MetricEvidenceShare, operations.OutcomeNoEvidence: MetricNoEvidenceShare,
			operations.OutcomePartial: MetricPartialShare, operations.OutcomeFailed: MetricFailedShare,
			operations.OutcomeReconcile: MetricReconciliationShare, operations.OutcomeCancelled: MetricCancelledShare,
		} {
			out = append(out, share(metric, dim, w, ended[key{r.AutomationID, outcome}], r.Executions, nil))
		}
		out = append(out,
			share(MetricInterventionShare, dim, w, r.Intervened, r.Executions, nil),
			share(MetricCompensationShare, dim, w, r.Compensated, r.Executions, nil),
			share(MetricRevertedShare, dim, w, r.Reverted, r.Executions, nil),
		)
	}
	return out, nil
}
