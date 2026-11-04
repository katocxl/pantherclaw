// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app runs behavior analytics (G0 M27 D501, D502, D506; F930-F934):
// a rollup job over an org's own pc.transactions and the two reads of
// BehaviorService. The job is off the decision path and nothing on that path
// imports this package (HR-641). What it raises is labeled inference,
// capped at ALERT, and can never contain by itself (HR-640, HR-644).
package app

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// Bounds of one org's rollup.
const (
	// MaxBatch is the most actions one run compares per origin, oldest
	// first; the cursor stops where they end and the next run goes on.
	MaxBatch = 20_000
	// MaxBaseline is the most known actions read per agent and origin for a
	// baseline; the newest are kept and the profile says it was truncated.
	MaxBaseline = 20_000
	// MaxAgents is the most agents one run profiles per origin.
	MaxAgents = 2_000
	// MaxSignals is the most alerts one rollup raises per origin. The rest
	// report one owned failure.
	MaxSignals = 200
	// MaxSignalsPerAgent is each agent's share of MaxSignals.
	MaxSignalsPerAgent = 20
	// settleAfter keeps the newest actions for the next run: a transaction
	// stamped before this one started may not have committed yet.
	settleAfter = 2 * time.Minute
	// ruleRoot extends pc.drift.behavior (F399): the kind is its last part.
	ruleRoot = "pc.drift.behavior."
)

// Owned failure kinds.
const (
	failureLapsed   = "behavior.edition_lapsed"
	failureOverflow = "behavior.signal_overflow"
	// FailureCapReached is BEHAVIOR_CAP_REACHED (D526) in the owned-failure
	// kind format.
	FailureCapReached = "behavior.cap_reached"
)

// Entitlements reads the org's licence.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Rollup is one org's profile job.
type Rollup struct {
	Pool     *db.Pool
	Ents     Entitlements
	Raiser   reflexports.Raiser
	Failures reflexports.FailureSink
	// Settle overrides settleAfter; tests set it.
	Settle time.Duration
	// MaxBatch, MaxBaseline and MaxAgents override the bounds; tests set
	// them.
	MaxBatch, MaxBaseline, MaxAgents int
}

// Result says what a run did.
type Result struct {
	Profiles, Signals int
}

// Run rolls up an org's real and simulated activity, each apart (HR-642). A
// first run starts collection and compares nothing, so old history raises no
// alerts. A lapsed edition stops quietly: earlier profiles stay and one
// owned failure says why.
func (r *Rollup) Run(ctx context.Context, org ids.OrgID) (Result, error) {
	ok, err := r.entitled(ctx)
	if err != nil {
		return Result{}, err
	}
	var res Result
	err = r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if !ok {
			return r.lapsed(ctx, tx, org)
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		now = now.Add(-cmp.Or(r.Settle, settleAfter))
		for _, origin := range []bdomain.Origin{bdomain.OriginReal, bdomain.OriginSimulated} {
			n, err := r.origin(ctx, tx, origin, now)
			if err != nil {
				return err
			}
			res.Profiles += n.Profiles
			res.Signals += n.Signals
		}
		return nil
	})
	return res, err
}

func (r *Rollup) entitled(ctx context.Context) (bool, error) {
	if r.Ents == nil {
		return false, nil
	}
	e, err := r.Ents.Current(ctx)
	if err != nil {
		return false, err
	}
	return e.BehaviorAnalytics(), nil
}

func (r *Rollup) lapsed(ctx context.Context, tx db.TenantTx, org ids.OrgID) error {
	started, err := dbq.New(tx).BehaviorCollectionStarted(ctx, org)
	if err != nil || !started || r.Failures == nil {
		return err
	}
	_, err = r.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: org, Kind: failureLapsed, DedupeKey: failureLapsed,
		Summary:  "Behavior analytics stopped: the edition no longer includes them. Earlier profiles are kept.",
		NextStep: "Renew a Business or higher licence to resume the rollup.",
		Deadline: time.Now().Add(7 * 24 * time.Hour),
	})
	return err
}

// origin rolls up one origin: it compares the page of actions since the
// cursor, each agent's against its known actions before the cursor, saves
// each active agent's profile as of the page's end, and moves the cursor
// over what it processed and no further (D526).
func (r *Rollup) origin(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, now time.Time) (Result, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	row, err := q.BehaviorScannedTo(ctx, org, string(origin))
	first := db.IsNoRows(err)
	if err != nil && !first {
		return Result{}, err
	}
	from := key{At: row.ScannedTo, ID: row.ScannedID}
	scanned := from.At
	var capped []string
	to := key{At: now}
	var deviations []found
	if !first {
		batch, cutoff, cut, err := loadBatch(ctx, q, org, origin, from, now, cmp.Or(r.MaxBatch, MaxBatch))
		if err != nil {
			return Result{}, err
		}
		if cut {
			capped = append(capped, "the actions one run compares")
		}
		to = cutoff
		byAgent := map[ids.UUID][]bdomain.Action{}
		for _, a := range batch {
			byAgent[a.Agent] = append(byAgent[a.Agent], a)
		}
		for _, agent := range sortedAgents(byAgent) {
			p, cut, err := baseline(ctx, q, org, agent, origin, scanned.Add(-bdomain.Window), scanned, cmp.Or(r.MaxBaseline, MaxBaseline))
			if err != nil {
				return Result{}, err
			}
			if cut {
				capped = append(capped, "an agent's baseline")
			}
			for _, d := range bdomain.Compare(p, byAgent[agent]) {
				deviations = append(deviations, found{Deviation: d, profile: p})
			}
		}
	}
	res, more, err := r.profiles(ctx, q, org, origin, to.At)
	if err != nil {
		return Result{}, err
	}
	capped = append(capped, more...)
	if res.Signals, err = r.raise(ctx, tx, origin, deviations, now); err != nil {
		return Result{}, err
	}
	if len(capped) > 0 {
		if err := r.capReached(ctx, tx, origin, capped, now); err != nil {
			return Result{}, err
		}
	}
	return res, advance(ctx, q, org, origin, first, from, to)
}

// profiles saves the profile, as of until, of each agent active in the
// window before it, at most MaxAgents.
func (r *Rollup) profiles(ctx context.Context, q *dbq.Queries, org ids.OrgID, origin bdomain.Origin, until time.Time) (Result, []string, error) {
	since := until.Add(-bdomain.Window)
	maxAgents := cmp.Or(r.MaxAgents, MaxAgents)
	agents, err := q.BehaviorAgents(ctx, dbq.BehaviorAgentsParams{
		OrgID: org, Simulated: origin == bdomain.OriginSimulated, Since: since, Until: until, MaxRows: int32(maxAgents), //nolint:gosec // a small bound
	})
	if err != nil {
		return Result{}, nil, err
	}
	var capped []string
	if len(agents) == maxAgents {
		capped = append(capped, "the agents one run profiles")
	}
	var res Result
	baselineCut := false
	for _, agent := range agents {
		p, cut, err := baseline(ctx, q, org, agent, origin, since, until, cmp.Or(r.MaxBaseline, MaxBaseline))
		if err != nil {
			return Result{}, nil, err
		}
		baselineCut = baselineCut || cut
		if err := saveProfile(ctx, q, org, p); err != nil {
			return Result{}, nil, err
		}
		res.Profiles++
	}
	if baselineCut {
		capped = append(capped, "an agent's baseline")
	}
	return res, capped, nil
}

func advance(ctx context.Context, q *dbq.Queries, org ids.OrgID, origin bdomain.Origin, first bool, from, to key) error {
	if first {
		_, err := q.StartBehaviorCursor(ctx, org, string(origin), to.At)
		return err
	}
	n, err := q.AdvanceBehaviorCursor(ctx, dbq.AdvanceBehaviorCursorParams{
		ScannedTo: to.At, ScannedID: to.ID, OrgID: org, Origin: string(origin), FromTime: from.At, FromID: from.ID,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("behavior: the %s cursor moved", origin)
	}
	return nil
}

func sortedAgents(m map[ids.UUID][]bdomain.Action) []ids.UUID {
	out := slices.Collect(maps.Keys(m))
	slices.SortFunc(out, func(a, b ids.UUID) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// key is the rollup cursor, a keyset on (created_at, id): every transaction
// up to it, in that order, has been compared. A zero ID means none at At.
type key struct {
	At time.Time
	ID ids.UUID
}

// loadBatch reads one origin's actions after since and before until, in
// (created_at, id) order, at most maxRows of them. It returns them, the key
// the cursor may move to, and whether the cap bit. A capped page ends at its
// last row, so the next run starts right after it and no row is skipped,
// however many share an instant (D548).
func loadBatch(ctx context.Context, q *dbq.Queries, org ids.OrgID, origin bdomain.Origin, since key, until time.Time, maxRows int) (
	[]bdomain.Action, key, bool, error,
) {
	rows, err := q.BehaviorBatch(ctx, dbq.BehaviorBatchParams{
		OrgID: org, Simulated: origin == bdomain.OriginSimulated, Since: since.At, SinceID: since.ID, Until: until,
		MaxRows: int32(maxRows), //nolint:gosec // a small bound
	})
	if err != nil {
		return nil, key{}, false, err
	}
	cutoff, cut := key{At: until}, len(rows) == maxRows
	if cut {
		last := rows[len(rows)-1]
		cutoff = key{At: last.CreatedAt, ID: last.ID}
	}
	out := make([]bdomain.Action, 0, len(rows))
	for _, x := range rows {
		a := bdomain.Action{
			ID: x.ID, Agent: x.AgentID, Run: x.RunID, Operation: x.Operation, DestClass: x.DestinationClass, At: x.CreatedAt,
			Known: known(x.Decision, x.State),
		}
		if x.ConnectionID != nil {
			a.Connection = *x.ConnectionID
		}
		if a.Known && x.Amount != nil && x.Currency != nil {
			a.Spent, a.Currency = x.Amount, *x.Currency
		}
		out = append(out, a)
	}
	return out, cutoff, cut, nil
}

// baseline is the profile of one agent's known actions of one origin in
// [since, until): allowed (a FINAL decision), plus generated history for SIMULATED
// (HR-642). Held, denied and open actions are only counted. At most maxRows
// of each kind are read, the newest; cut says the cap bit (D526).
func baseline(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, origin bdomain.Origin, since, until time.Time,
	maxRows int,
) (bdomain.BehaviorProfile, bool, error) {
	simulated := origin == bdomain.OriginSimulated
	rows, err := q.BehaviorKnownActions(ctx, dbq.BehaviorKnownActionsParams{
		OrgID: org, AgentID: agent, Simulated: simulated, Since: since, Until: until, MaxRows: int32(maxRows), //nolint:gosec // a small bound
	})
	if err != nil {
		return bdomain.BehaviorProfile{}, false, err
	}
	actions := make([]bdomain.Action, 0, len(rows))
	for _, x := range rows {
		a := bdomain.Action{
			ID: x.ID, Agent: agent, Run: x.RunID, Operation: x.Operation, DestClass: x.DestinationClass, At: x.CreatedAt, Known: true,
		}
		if x.ConnectionID != nil {
			a.Connection = *x.ConnectionID
		}
		if x.Amount != nil && x.Currency != nil {
			a.Spent, a.Currency = x.Amount, *x.Currency
		}
		actions = append(actions, a)
	}
	cut := len(rows) == maxRows
	if simulated {
		hist, err := q.BehaviorSimulatedHistory(ctx, dbq.BehaviorSimulatedHistoryParams{
			OrgID: org, AgentID: agent, Since: since, Until: until, MaxRows: int32(maxRows), //nolint:gosec // a small bound
		})
		if err != nil {
			return bdomain.BehaviorProfile{}, false, err
		}
		for _, x := range hist {
			a := bdomain.Action{
				ID: x.ID, Agent: agent, Run: x.RunRef, Operation: x.Operation, DestClass: x.DestinationClass, At: x.OccurredAt,
				Generated: true, Known: true,
			}
			if x.ConnectionID != nil {
				a.Connection = *x.ConnectionID
			}
			if x.Amount != nil && x.Currency != nil {
				a.Spent, a.Currency = x.Amount, *x.Currency
			}
			actions = append(actions, a)
		}
		cut = cut || len(hist) == maxRows
	}
	other, err := q.BehaviorNotAllowedCount(ctx, dbq.BehaviorNotAllowedCountParams{
		OrgID: org, AgentID: agent, Simulated: simulated, Since: since, Until: until,
	})
	if err != nil {
		return bdomain.BehaviorProfile{}, false, err
	}
	p := bdomain.Build(agent, origin, actions, since, until, cut)
	p.Body.NotAllowed += other
	return p, cut, nil
}

// known: allowed, a FINAL decision (00025: OPEN or FINAL is the decision's
// state, not execution). An OPEN transaction is still being evaluated.
func known(decision, state string) bool {
	return (decision == "ALLOW" || decision == "ALLOW_WITH_OBLIGATIONS") && state == "FINAL"
}

func saveProfile(ctx context.Context, q *dbq.Queries, org ids.OrgID, p bdomain.BehaviorProfile) error {
	body, err := json.Marshal(p.Body, json.Deterministic(true))
	if err != nil {
		return err
	}
	return q.UpsertBehaviorProfile(ctx, dbq.UpsertBehaviorProfileParams{
		OrgID: org, AgentID: p.Agent, Origin: string(p.Origin), State: string(p.State), WindowStart: p.Start, WindowEnd: p.End,
		Actions: p.Actions, ActiveDays: int32(p.ActiveDays), //nolint:gosec // at most 31 days
		Method: bdomain.Method, Truncated: p.Truncated, Body: body,
	})
}

// found is a deviation and the profile it was measured against.
type found struct {
	bdomain.Deviation
	profile bdomain.BehaviorProfile
}

// raise raises at most MaxSignals alerts, each agent at most
// MaxSignalsPerAgent, taken in turn across agents so one agent can't crowd
// the others out. What is left is counted in one overflow failure (D548).
func (r *Rollup) raise(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, ds []found, now time.Time) (int, error) {
	chosen := shares(ds)
	raised := 0
	for _, d := range chosen {
		if _, err := r.Raiser.Raise(ctx, tx.Pgx(), signal(tx.OrgID(), origin, d)); err != nil {
			return raised, err
		}
		raised++
	}
	if more := len(ds) - raised; more > 0 {
		return raised, r.overflow(ctx, tx, origin, more, now)
	}
	return raised, nil
}

// shares picks the deviations one run raises: in turn across agents (in
// the order they first appear), at most MaxSignalsPerAgent each and
// MaxSignals in all.
func shares(ds []found) []found {
	var order []ids.UUID
	byAgent := map[ids.UUID][]found{}
	for _, d := range ds {
		a := d.Action.Agent
		if _, ok := byAgent[a]; !ok {
			order = append(order, a)
		}
		byAgent[a] = append(byAgent[a], d)
	}
	var out []found
	for turn := 0; turn < MaxSignalsPerAgent && len(out) < MaxSignals; turn++ {
		for _, a := range order {
			if turn < len(byAgent[a]) && len(out) < MaxSignals {
				out = append(out, byAgent[a][turn])
			}
		}
	}
	return out
}

func (r *Rollup) overflow(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, more int, now time.Time) error {
	if r.Failures == nil {
		return nil
	}
	_, err := r.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: tx.OrgID(), Kind: failureOverflow, DedupeKey: failureOverflow + ":" + string(origin),
		Summary:  fmt.Sprintf("Behavior analytics found %d more %s deviations than one run raises.", more, strings.ToLower(string(origin))),
		NextStep: "Look at the agents already flagged: a burst this wide usually shares a cause.",
		Deadline: now.Add(7 * 24 * time.Hour),
	})
	return err
}

// capReached reports BEHAVIOR_CAP_REACHED: a bound of the method bit, so
// this run left something out (D526).
func (r *Rollup) capReached(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, what []string, now time.Time) error {
	if r.Failures == nil {
		return nil
	}
	slices.Sort(what)
	_, err := r.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: tx.OrgID(), Kind: FailureCapReached, DedupeKey: FailureCapReached + ":" + string(origin),
		Summary: fmt.Sprintf("BEHAVIOR_CAP_REACHED: behavior analytics reached a bound on %s activity (%s). "+
			"A capped page is carried on by the next run; a capped baseline keeps only the newest actions.",
			strings.ToLower(string(origin)), strings.Join(slices.Compact(what), ", ")),
		NextStep: "Read the affected profiles as truncated. If this repeats, the org's volume outruns the method's bounds.",
		Deadline: now.Add(7 * 24 * time.Hour),
	})
	return err
}

// severities and attentions of the kinds. Nothing exceeds ALERT: a person
// reads an inference, and it opens no incident by itself (HR-644).
var attention = map[bdomain.Kind]reflexdomain.Attention{
	bdomain.KindNewTool: reflexdomain.AttentionFinding, bdomain.KindUnusualHour: reflexdomain.AttentionFinding,
	bdomain.KindNewSequence: reflexdomain.AttentionFinding, bdomain.KindVolumeSpike: reflexdomain.AttentionFinding,
	bdomain.KindNewDestination: reflexdomain.AttentionAlert, bdomain.KindSpendSpike: reflexdomain.AttentionAlert,
}

var severity = map[bdomain.Kind]reflexdomain.Severity{
	bdomain.KindNewTool: reflexdomain.SeverityLow, bdomain.KindUnusualHour: reflexdomain.SeverityLow,
	bdomain.KindNewSequence: reflexdomain.SeverityLow, bdomain.KindVolumeSpike: reflexdomain.SeverityMedium,
	bdomain.KindNewDestination: reflexdomain.SeverityMedium, bdomain.KindSpendSpike: reflexdomain.SeverityMedium,
}

// signal is a deviation as a Reflex signal: labeled inference, on the
// agent, and SIMULATED rests apart as a test signal, which never pages
// (HR-222, HR-644).
func signal(org ids.OrgID, origin bdomain.Origin, d found) reflexdomain.Signal {
	a := d.Action
	rule := ruleRoot + strings.ToLower(string(d.Kind))
	digest := sha256.Sum256([]byte(rule + "|" + bdomain.Method))
	subjects := []reflexdomain.Subject{
		{Type: reflexdomain.SubjectAgent, ID: a.Agent.String()},
		{Type: reflexdomain.SubjectRun, ID: a.Run.String()},
		{Type: reflexdomain.SubjectTransaction, ID: a.ID.String()},
	}
	evidence := []reflexdomain.EvidenceRef{
		{Kind: reflexdomain.EvidenceTransaction, ID: a.ID}, {Kind: reflexdomain.EvidenceRun, ID: a.Run},
	}
	if !a.Connection.IsZero() {
		subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectConnection, ID: a.Connection.String()})
	}
	value := d.Value
	if len(value) > reflexdomain.MaxFactValue {
		value = value[:reflexdomain.MaxFactValue]
	}
	// The kind's techniques label the alert (G0 M28 D718).
	m := mapping.Kinds["behavior."+string(d.Kind)]
	return reflexdomain.Signal{
		ATLAS: slices.Clone(m.ATLAS), ATTACK: slices.Clone(m.ATTACK),
		Org: org, Source: reflexdomain.SourceBehavior, RuleID: rule, RuleVersion: bdomain.Method,
		RuleDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Title:      title(origin, d.Kind), Summary: d.Text + ". " + bdomain.Label,
		Severity: severity[d.Kind], Attention: attention[d.Kind], Basis: reflexdomain.BasisInferred,
		Subjects: subjects, Evidence: evidence, GroupKey: "agent:" + a.Agent.String(),
		DedupeKey:  string(reflexdomain.SourceBehavior) + "|" + rule + "|" + a.Agent.String() + "|" + hashed(value),
		OccurredAt: a.At, Test: origin == bdomain.OriginSimulated,
		Facts: map[string]string{
			"kind": string(d.Kind), "value": value, "origin": string(origin), "basis": bdomain.Basis,
			"definition_status": bdomain.DefinitionStatus, "profile_method": bdomain.Method,
			"profile_actions": strconv.FormatInt(d.profile.Actions, 10), "profile_days": strconv.Itoa(d.profile.ActiveDays),
		},
	}
}

func hashed(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func title(origin bdomain.Origin, k bdomain.Kind) string {
	words := map[bdomain.Kind]string{
		bdomain.KindNewTool: "Agent used a tool it hadn't used", bdomain.KindNewDestination: "Agent used a new connection",
		bdomain.KindUnusualHour: "Agent acted at an unusual hour", bdomain.KindNewSequence: "Agent ran an unusual sequence",
		bdomain.KindVolumeSpike: "Agent's activity spiked", bdomain.KindSpendSpike: "Agent's spending spiked",
	}[k]
	if origin == bdomain.OriginSimulated {
		return "SIMULATED: " + words
	}
	return words
}
