// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app runs behaviour analytics (G0 M27 D501, D502, D506; F930-F934):
// a rollup job over an org's own pc.transactions and the two reads of
// BehaviorService. The job is off the decision path and nothing on that path
// imports this package (HR-641). What it raises is labelled inference,
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
)

// Bounds of one org's rollup.
const (
	// MaxActions is the most actions one origin reads; the newest are kept
	// and the profile says it was truncated.
	MaxActions = 50_000
	// MaxSignals is the most alerts one rollup raises per origin. The rest
	// report one owned failure.
	MaxSignals = 200
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
		Summary:  "Behaviour analytics stopped: the edition no longer includes them. Earlier profiles are kept.",
		NextStep: "Renew a Business or higher licence to resume the rollup.",
		Deadline: time.Now().Add(7 * 24 * time.Hour),
	})
	return err
}

func (r *Rollup) origin(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, now time.Time) (Result, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	scanned, err := q.BehaviorScannedTo(ctx, org, string(origin))
	first := db.IsNoRows(err)
	if err != nil && !first {
		return Result{}, err
	}
	start := now.Add(-bdomain.Window)
	actions, cut, err := loadActions(ctx, q, org, origin, start, now)
	if err != nil {
		return Result{}, err
	}
	byAgent := map[ids.UUID][]bdomain.Action{}
	for _, a := range actions {
		byAgent[a.Agent] = append(byAgent[a.Agent], a)
	}
	var res Result
	var deviations []found
	for _, agent := range sortedAgents(byAgent) {
		all := byAgent[agent]
		if !first {
			// Generated history is never a new action, however it is dated.
			newer := func(a bdomain.Action) bool { return !a.At.Before(scanned) && !a.Generated }
			older := slices.DeleteFunc(slices.Clone(all), newer)
			batch := slices.DeleteFunc(slices.Clone(all), func(a bdomain.Action) bool { return !newer(a) })
			p := bdomain.Build(agent, origin, older, start, scanned, cut)
			for _, d := range bdomain.Compare(p, batch) {
				deviations = append(deviations, found{Deviation: d, profile: p})
			}
		}
		if err := saveProfile(ctx, q, org, bdomain.Build(agent, origin, all, start, now, cut)); err != nil {
			return Result{}, err
		}
		res.Profiles++
	}
	if res.Signals, err = r.raise(ctx, tx, origin, deviations, now); err != nil {
		return Result{}, err
	}
	return res, advance(ctx, q, org, origin, first, scanned, now)
}

func advance(ctx context.Context, q *dbq.Queries, org ids.OrgID, origin bdomain.Origin, first bool, from, to time.Time) error {
	if first {
		_, err := q.StartBehaviorCursor(ctx, org, string(origin), to)
		return err
	}
	n, err := q.AdvanceBehaviorCursor(ctx, dbq.AdvanceBehaviorCursorParams{
		ScannedTo: to, OrgID: org, Origin: string(origin), FromTime: from,
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

// loadActions reads one origin's actions, newest first, and whether a cap
// cut them. A real read never touches the simulated table.
func loadActions(ctx context.Context, q *dbq.Queries, org ids.OrgID, origin bdomain.Origin, since, until time.Time) ([]bdomain.Action, bool, error) {
	rows, err := q.BehaviorActions(ctx, dbq.BehaviorActionsParams{
		OrgID: org, Simulated: origin == bdomain.OriginSimulated, Since: since, Until: until, MaxRows: MaxActions,
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]bdomain.Action, 0, len(rows))
	for _, x := range rows {
		a := bdomain.Action{
			ID: x.ID, Agent: x.AgentID, Run: x.RunID, Operation: x.Operation, DestClass: x.DestinationClass, At: x.CreatedAt,
		}
		if x.ConnectionID != nil {
			a.Connection = *x.ConnectionID
		}
		if allowed(x.Decision) && x.Amount != nil && x.Currency != nil {
			a.Spent, a.Currency = x.Amount, *x.Currency
		}
		out = append(out, a)
	}
	cut := len(rows) == MaxActions
	if origin != bdomain.OriginSimulated {
		return out, cut, nil
	}
	hist, err := q.BehaviorSimulatedHistory(ctx, dbq.BehaviorSimulatedHistoryParams{
		OrgID: org, Since: since, Until: until, MaxRows: MaxActions,
	})
	if err != nil {
		return nil, false, err
	}
	for _, x := range hist {
		a := bdomain.Action{
			ID: x.ID, Agent: x.AgentID, Run: x.RunRef, Operation: x.Operation, DestClass: x.DestinationClass, At: x.OccurredAt,
			Generated: true,
		}
		if x.ConnectionID != nil {
			a.Connection = *x.ConnectionID
		}
		if x.Amount != nil && x.Currency != nil {
			a.Spent, a.Currency = x.Amount, *x.Currency
		}
		out = append(out, a)
	}
	return out, cut || len(hist) == MaxActions, nil
}

func allowed(decision string) bool {
	return decision == "ALLOW" || decision == "ALLOW_WITH_OBLIGATIONS"
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

func (r *Rollup) raise(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, ds []found, now time.Time) (int, error) {
	raised := 0
	for i, d := range ds {
		if i == MaxSignals {
			return raised, r.overflow(ctx, tx, origin, len(ds)-i, now)
		}
		if _, err := r.Raiser.Raise(ctx, tx.Pgx(), signal(tx.OrgID(), origin, d)); err != nil {
			return raised, err
		}
		raised++
	}
	return raised, nil
}

func (r *Rollup) overflow(ctx context.Context, tx db.TenantTx, origin bdomain.Origin, more int, now time.Time) error {
	if r.Failures == nil {
		return nil
	}
	_, err := r.Failures.Report(ctx, tx.Pgx(), reflexdomain.Failure{
		Org: tx.OrgID(), Kind: failureOverflow, DedupeKey: failureOverflow + ":" + string(origin),
		Summary:  fmt.Sprintf("Behaviour analytics found %d more %s deviations than one run raises.", more, strings.ToLower(string(origin))),
		NextStep: "Look at the agents already flagged: a burst this wide usually shares a cause.",
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

// signal is a deviation as a Reflex signal: labelled inference, on the
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
	return reflexdomain.Signal{
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
