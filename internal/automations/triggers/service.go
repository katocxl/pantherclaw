// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package triggers decides which outside occurrences start automation
// executions (G0 M11 part 2 D16–D23; HR-276..278, T-122, T-123): schedules,
// platform events, conditions and thresholds, manual starts and signed
// inbound events all become one trigger record, accepted or refused, and
// an accepted trigger starts its execution through the engine's Starter in
// the same transaction.
//
// Every trigger passes the same checks in one order: its parameters
// (declared, typed, bounded), its ancestry (no automation upstream of
// itself, depth below 4), the active window, the dedupe keys (one
// execution per key), the definition's `if`, the paused policy, the
// hourly cap, and the engine's own revalidation at start. Refusals are
// recorded; loops and caps raise one grouped issue each.
package triggers

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// State is a trigger record's state (D16).
type State string

// Trigger states.
const (
	StateAccepted           State = "ACCEPTED"
	StateShadow             State = "SHADOW"
	StateQueued             State = "QUEUED"
	StateDiscarded          State = "DISCARDED"
	StateExpired            State = "EXPIRED"
	StateRefusedDuplicate   State = "REFUSED_DUPLICATE"
	StateRefusedLoop        State = "REFUSED_LOOP"
	StateRefusedLimit       State = "REFUSED_LIMIT"
	StateRefusedConcurrency State = "REFUSED_CONCURRENCY"
	StateRefusedInvalid     State = "REFUSED_INVALID"
	StateRefusedCondition   State = "REFUSED_CONDITION"
	StateRefusedWindow      State = "REFUSED_WINDOW"
)

// Started reports whether a trigger in s started (or will start) work.
func (s State) Started() bool { return s == StateAccepted || s == StateShadow }

// Reasons recorded with a trigger.
const (
	ReasonParams         = "PARAMS"
	ReasonLoop           = "ANCESTRY"
	ReasonDepth          = "DEPTH"
	ReasonWidth          = "ANCESTRY_WIDTH"
	ReasonParamsSize     = "PARAMS_SIZE"
	ReasonWindow         = "OUTSIDE_WINDOW"
	ReasonDuplicate      = "DUPLICATE"
	ReasonCondition      = "IF_FALSE"
	ReasonConditionError = "IF_ERROR"
	ReasonPaused         = "PAUSED"
	ReasonQueueFull      = "QUEUE_FULL"
	ReasonQueueTTL       = "QUEUE_TTL"
	ReasonVersionChanged = "VERSION_CHANGED"
	ReasonHourlyCap      = "HOURLY_CAP"
	ReasonConcurrency    = "CONCURRENCY"
	ReasonNotActive      = "NOT_ACTIVE"
	ReasonNoEngine       = "ENGINE_UNAVAILABLE"
	ReasonMissed         = "MISSED"
	ReasonRetired        = "RETIRED"
)

// Owned failure kinds and signal rule (D19, D23).
const (
	FailureLoopStopped       = "automation.loop_stopped"
	FailureHourlyCap         = "automation.hourly_cap"
	FailureProbeOverflow     = "automation.probe_overflow"
	FailureThresholdOverflow = "automation.threshold_overflow"
	FailureTriggerError      = "automation.trigger_error"
	RuleLoop                 = "automation.loop"
)

// Queue defaults when a definition sets none (D2: queue_max ≤ 100,
// queue_ttl ≤ 24h).
const (
	DefaultQueueMax = 100
	DefaultQueueTTL = 24 * time.Hour
)

// Actor is the system actor of trigger records.
var Actor = evdomain.Actor{Type: "system", ID: "automations"}

// Editions reports the licence.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Operations returns the org's active definition of an exact operation
// (nil when there is none), in the trigger's transaction (D97 N3).
type Operations interface {
	Active(ctx context.Context, tx db.TenantTx, org ids.OrgID, op string) (*defs.Definition, error)
}

// Deps are the service's collaborators. Ports left nil are "not
// available": a nil Starter refuses every start (ENGINE_UNAVAILABLE), a
// nil Pauser leaves a looping automation running but still refuses its
// triggers.
type Deps struct {
	Pool       *db.Pool
	Starter    autoports.Starter
	Pauser     autoports.Pauser
	Raiser     reflexports.Raiser
	Failures   reflexports.FailureSink
	Editions   Editions
	Executions ExecutionLookup
	// Operations reads operation definitions (irreversible ceiling
	// operations force a manual step-up, D87 P3); nil: every ceiling
	// operation counts as irreversible.
	Operations Operations
	Clock      clock.Clock
	Log        *slog.Logger
}

// Service is the trigger service.
type Service struct{ d Deps }

// New returns the service.
func New(d Deps) *Service {
	if d.Clock == nil {
		d.Clock = clock.System{}
	}
	if d.Log == nil {
		d.Log = pclog.Discard()
	}
	return &Service{d: d}
}

// WithStarter sets the engine's Starter (wired once the engine exists).
func (s *Service) WithStarter(st autoports.Starter) *Service {
	s.d.Starter = st
	return s
}

// WithExecutions sets the execution lookup retries need (D59).
func (s *Service) WithExecutions(x ExecutionLookup) *Service {
	s.d.Executions = x
	return s
}

// Automation is an ACTIVE or PAUSED automation with its enabled version.
type Automation struct {
	ID             ids.UUID
	Name           string
	State          autodomain.State
	Rollout        autodomain.Rollout
	ServiceAccount ids.UUID
	Owner          ids.UUID
	Version        ids.UUID
	Def            *autodomain.Definition
}

func automationOf(id ids.UUID, name, state string, rollout *string, sa, owner, version ids.UUID, def []byte) (Automation, error) {
	d, err := autodomain.Parse(def)
	if err != nil {
		return Automation{}, fmt.Errorf("triggers: automation %s: stored definition: %w", id, err)
	}
	a := Automation{
		ID: id, Name: name, State: autodomain.State(state), ServiceAccount: sa, Owner: owner, Version: version, Def: d,
	}
	if rollout != nil {
		a.Rollout = autodomain.Rollout(*rollout)
	}
	return a, nil
}

// Candidate is one occurrence for one automation.
type Candidate struct {
	Automation   Automation
	Kind         autodomain.TriggerKind
	Authenticity autodomain.Authenticity
	// Detail is the authenticity detail: source id and secret generation;
	// user and credential; ledger seq; schedule occurrence.
	Detail    map[string]string
	SourceRef string
	Params    map[string]autodomain.Value
	// ParamErr is the extraction failure, if any: the trigger is refused.
	ParamErr   error
	Subjects   []reflexdomain.Subject
	Evidence   []reflexdomain.EvidenceRef
	Lineage    Lineage
	BaseKey    string
	OccurredAt time.Time
	// Mode overrides the rollout's mode (TEST, for assurance); "" reads
	// SHADOW from a SHADOW rollout and LIVE otherwise.
	Mode        autodomain.Mode
	RetriedFrom *ids.UUID
	// QueueOK: a paused automation may queue this trigger. False for a
	// missed schedule occurrence, which is never replayed.
	QueueOK bool
}

// Outcome is what became of a candidate.
type Outcome struct {
	Trigger   ids.UUID
	State     State
	Reason    string
	Execution ids.UUID
}

// Fire records one candidate and, when accepted, starts its execution, in
// tx (HR-276..278).
func (s *Service) Fire(ctx context.Context, tx db.TenantTx, c Candidate) (Outcome, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	a := c.Automation
	def := a.Def
	now, err := q.DBNow(ctx)
	if err != nil {
		return Outcome{}, err
	}
	if c.OccurredAt.IsZero() {
		c.OccurredAt = now
	}
	id := ids.NewV7()
	lin := c.Lineage
	if lin.Depth == 0 {
		lin = Lineage{Root: id}
	}
	mode := c.Mode
	if mode == "" {
		mode = autodomain.ModeLive
		if a.Rollout == autodomain.RolloutShadow {
			mode = autodomain.ModeShadow
		}
	}
	ref := autodomain.TriggerRef{
		ID: id, Org: org, Automation: a.ID, Version: a.Version, Kind: c.Kind, Mode: mode, Params: c.Params,
		Subjects: c.Subjects, Evidence: c.Evidence, Root: lin.Root, Ancestry: lin.Ancestry, Depth: lin.Depth,
		OccurredAt: c.OccurredAt,
	}
	declKey := DedupeKey(def, ref)

	state, reason, err := s.decide(ctx, q, org, c, lin, ref, declKey, now)
	if err != nil {
		return Outcome{}, err
	}
	var queuedUntil *time.Time
	if state == StateQueued {
		if ttl := queueTTL(def); ttl > 0 {
			t := now.Add(ttl)
			queuedUntil = &t
		}
	}
	// A key is claimed only by a trigger that starts or queues work; a
	// race lost here is a duplicate (HR-277).
	if state.Started() || state == StateQueued {
		ok, err := s.claim(ctx, q, org, a.ID, id, c.BaseKey, now.Add(BaseKeyWindow))
		if err == nil && ok && declKey != "" {
			ok, err = s.claim(ctx, q, org, a.ID, id, declKey, now.Add(DedupeWindow(def)))
		}
		if err != nil {
			return Outcome{}, err
		}
		if !ok {
			if err := q.ReleaseDedupeKeys(ctx, org, id); err != nil {
				return Outcome{}, err
			}
			state, reason, queuedUntil = StateRefusedDuplicate, ReasonDuplicate, nil
		}
	}
	if err := s.insert(ctx, q, org, id, c, ref, lin, state, reason, queuedUntil); err != nil {
		return Outcome{}, err
	}
	out := Outcome{Trigger: id, State: state, Reason: reason}
	if state.Started() {
		out, err = s.start(ctx, tx, ref, out)
		if err != nil {
			return Outcome{}, err
		}
	}
	if err := s.after(ctx, tx, c, lin, out, now); err != nil {
		return Outcome{}, err
	}
	return out, nil
}

// decide applies the checks in their fixed order.
func (s *Service) decide(ctx context.Context, q *dbq.Queries, org ids.OrgID, c Candidate, lin Lineage,
	ref autodomain.TriggerRef, declKey string, now time.Time,
) (State, string, error) {
	a, def := c.Automation, c.Automation.Def
	switch {
	case c.ParamErr != nil:
		return StateRefusedInvalid, ReasonParams, nil //nolint:nilerr // bad parameters are a recorded refusal
	case lin.Loop(a.ID):
		switch {
		case slices.Contains(lin.Ancestry, a.ID):
			return StateRefusedLoop, ReasonLoop, nil
		case len(lin.Ancestry) > autodomain.MaxAncestry:
			return StateRefusedLoop, ReasonWidth, nil
		}
		return StateRefusedLoop, ReasonDepth, nil
	case paramsTooLarge(ref.Params):
		return StateRefusedInvalid, ReasonParamsSize, nil
	case !inWindow(def, c.OccurredAt):
		return StateRefusedWindow, ReasonWindow, nil
	}
	for _, k := range []string{c.BaseKey, declKey} {
		if k == "" {
			continue
		}
		held, err := q.DedupeKeyHeld(ctx, org, a.ID, k)
		if err != nil {
			return "", "", err
		}
		if held {
			return StateRefusedDuplicate, ReasonDuplicate, nil
		}
	}
	ok, err := MatchIf(ctx, def.If, c.Kind, c.OccurredAt, ref.Params)
	switch {
	case err != nil:
		return StateRefusedCondition, ReasonConditionError, nil //nolint:nilerr // a failing `if` is a recorded refusal
	case !ok:
		return StateRefusedCondition, ReasonCondition, nil
	}
	if a.State == autodomain.StatePaused {
		st, why := s.pausedPolicy(ctx, q, org, c)
		return st, why, nil
	}
	if a.State != autodomain.StateActive {
		return StateRefusedInvalid, ReasonNotActive, nil
	}
	// The cap is counted under the automation's lock, so concurrent triggers
	// never overrun it (D87 L4). A failure is an error, never a refusal
	// (D97 N4).
	if _, err := q.LockAutomation(ctx, org, a.ID); err != nil {
		return "", "", err
	}
	n, err := q.CountStartedTriggersSince(ctx, org, a.ID, now.Add(-time.Hour))
	if err != nil {
		return "", "", err
	}
	if int(n) >= def.Limits.PerHourOrDefault() {
		return StateRefusedLimit, ReasonHourlyCap, nil
	}
	if ref.Mode == autodomain.ModeShadow {
		return StateShadow, "", nil
	}
	return StateAccepted, "", nil
}

func (s *Service) pausedPolicy(ctx context.Context, q *dbq.Queries, org ids.OrgID, c Candidate) (State, string) {
	def := c.Automation.Def
	if !c.QueueOK {
		return StateDiscarded, ReasonPaused
	}
	switch def.Paused {
	case autodomain.PausedQueue, autodomain.PausedExpire:
		n, err := q.CountQueuedTriggers(ctx, org, c.Automation.ID)
		if err != nil || int(n) >= queueMax(def) {
			return StateDiscarded, ReasonQueueFull
		}
		return StateQueued, ReasonPaused
	case autodomain.PausedDiscard:
	}
	return StateDiscarded, ReasonPaused
}

func queueMax(def *autodomain.Definition) int {
	if def.QueueMax > 0 && def.QueueMax <= DefaultQueueMax {
		return def.QueueMax
	}
	return DefaultQueueMax
}

// queueTTL is how long a queued trigger waits: queue_ttl when set (≤ 24h),
// 24h for EXPIRE; a QUEUE trigger without queue_ttl waits for the resume.
func queueTTL(def *autodomain.Definition) time.Duration {
	ttl := min(def.QueueTTL.D(), DefaultQueueTTL)
	if ttl <= 0 && def.Paused == autodomain.PausedExpire {
		ttl = DefaultQueueTTL
	}
	return ttl
}

func inWindow(def *autodomain.Definition, at time.Time) bool {
	w := def.When.Window
	if w == nil {
		return true
	}
	if !w.From.IsZero() && at.Before(w.From) {
		return false
	}
	return w.To.IsZero() || at.Before(w.To)
}

func (s *Service) claim(ctx context.Context, q *dbq.Queries, org ids.OrgID, automation, trigger ids.UUID, key string, until time.Time) (bool, error) {
	if key == "" {
		return true, nil
	}
	_, err := q.ClaimDedupeKey(ctx, dbq.ClaimDedupeKeyParams{
		OrgID: org, AutomationID: automation, Key: key, TriggerID: trigger, ExpiresAt: until,
	})
	if db.IsNoRows(err) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) insert(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, c Candidate,
	ref autodomain.TriggerRef, lin Lineage, state State, reason string, queuedUntil *time.Time,
) error {
	stored := ref.Params
	if reason == ReasonParamsSize {
		stored = nil // refused for its size: nothing of it is kept
	}
	params, err := json.Marshal(nonNilMap(stored), json.Deterministic(true))
	if err != nil {
		return err
	}
	// A refused chain wider than the bound keeps its first ancestors.
	ancestry := nonNilSlice(lin.Ancestry)
	if len(ancestry) > autodomain.MaxAncestry {
		ancestry = ancestry[:autodomain.MaxAncestry]
	}
	detail, err := json.Marshal(nonNilMap(c.Detail), json.Deterministic(true))
	if err != nil {
		return err
	}
	subjects, err := json.Marshal(nonNilSlice(c.Subjects))
	if err != nil {
		return err
	}
	evidence, err := json.Marshal(nonNilSlice(c.Evidence))
	if err != nil {
		return err
	}
	var r *string
	if reason != "" {
		r = &reason
	}
	src := c.SourceRef
	if src == "" {
		src = string(c.Kind)
	}
	return q.InsertAutomationTrigger(ctx, dbq.InsertAutomationTriggerParams{
		OrgID: org, ID: id, AutomationID: c.Automation.ID, VersionID: c.Automation.Version, Kind: string(c.Kind),
		Mode: string(ref.Mode), SourceRef: truncate(src, 256), Authenticity: string(c.Authenticity),
		AuthenticityDetail: detail, Params: params, Subjects: subjects, Evidence: evidence, RootTriggerID: lin.Root,
		Ancestry: ancestry, Depth: int32(min(lin.Depth, autodomain.MaxDepth)), //nolint:gosec // depth is 0..4
		State: string(state), Reason: r,
		RetriedFrom: c.RetriedFrom, QueuedUntil: queuedUntil, OccurredAt: c.OccurredAt,
	})
}

// start hands an accepted trigger to the engine in the same transaction.
// A refusal at start gives the trigger's keys back.
func (s *Service) start(ctx context.Context, tx db.TenantTx, ref autodomain.TriggerRef, out Outcome) (Outcome, error) {
	q := dbq.New(tx)
	refuse := func(st State, reason string) (Outcome, error) {
		n, err := q.SetTriggerState(ctx, dbq.SetTriggerStateParams{
			ToState: string(st), Reason: &reason, OrgID: ref.Org, ID: ref.ID, FromState: string(out.State),
		})
		if err != nil {
			return Outcome{}, err
		}
		if n != 1 {
			return Outcome{}, fmt.Errorf("triggers: trigger %s moved", ref.ID)
		}
		if err := q.ReleaseDedupeKeys(ctx, ref.Org, ref.ID); err != nil {
			return Outcome{}, err
		}
		out.State, out.Reason = st, reason
		return out, nil
	}
	if s.d.Starter == nil {
		return refuse(StateRefusedInvalid, ReasonNoEngine)
	}
	exec, err := s.d.Starter.Start(ctx, tx.Pgx(), ref)
	switch {
	case errors.Is(err, autodomain.ErrConcurrency):
		return refuse(StateRefusedConcurrency, ReasonConcurrency)
	case errors.Is(err, autodomain.ErrNotActive):
		return refuse(StateRefusedInvalid, ReasonNotActive)
	case err != nil:
		return Outcome{}, fmt.Errorf("triggers: start: %w", err)
	}
	n, err := q.AttachTriggerExecution(ctx, &exec, ref.Org, ref.ID)
	if err != nil {
		return Outcome{}, err
	}
	if n != 1 {
		return Outcome{}, fmt.Errorf("triggers: trigger %s moved", ref.ID)
	}
	out.Execution = exec
	return out, nil
}

// after records what an outcome owes: an audit record for accepted
// triggers, and one grouped issue per loop root or per hourly cap (D16,
// D23). Other refusals are quiet.
func (s *Service) after(ctx context.Context, tx db.TenantTx, c Candidate, lin Lineage, out Outcome, now time.Time) error {
	a := c.Automation
	switch out.State { //nolint:exhaustive // other refusals are quiet (D16)
	case StateAccepted, StateShadow:
		return s.audit(ctx, tx, "automation.triggered", a.ID, out.Trigger, map[string]string{
			"version": a.Version.String(), "kind": string(c.Kind), "mode": modeOf(out.State, c.Mode),
			"authenticity": string(c.Authenticity), "execution": out.Execution.String(), "depth": fmt.Sprint(lin.Depth),
		})
	case StateRefusedLoop:
		return s.loop(ctx, tx, c, lin, out, now)
	case StateRefusedLimit:
		return s.limit(ctx, tx, c, out, now)
	default:
		return nil
	}
}

func modeOf(st State, m autodomain.Mode) string {
	if m != "" {
		return string(m)
	}
	if st == StateShadow {
		return string(autodomain.ModeShadow)
	}
	return string(autodomain.ModeLive)
}

func (s *Service) loop(ctx context.Context, tx db.TenantTx, c Candidate, lin Lineage, out Outcome, now time.Time) error {
	q := dbq.New(tx)
	org, a := tx.OrgID(), c.Automation
	root := lin.Root
	earlier, err := q.CountRefusalsSince(ctx, dbq.CountRefusalsSinceParams{
		OrgID: org, State: string(StateRefusedLoop), ExceptID: out.Trigger, RootTriggerID: &root,
		Since: now.Add(-BaseKeyWindow),
	})
	if err != nil {
		return err
	}
	if s.d.Pauser != nil && a.State == autodomain.StateActive {
		if _, err := s.d.Pauser.Pause(ctx, tx.Pgx(), org, autodomain.PauseSelector{Automations: []ids.UUID{a.ID}}, autodomain.PauseLoop); err != nil {
			return fmt.Errorf("triggers: pause looping automation: %w", err)
		}
	}
	if earlier > 0 {
		return nil
	}
	subjects := []reflexdomain.Subject{{Type: reflexdomain.SubjectAutomation, ID: a.ID.String()}}
	for _, up := range lin.Ancestry {
		if len(subjects) < reflexdomain.MaxSubjects {
			subjects = append(subjects, reflexdomain.Subject{Type: reflexdomain.SubjectAutomation, ID: up.String()})
		}
	}
	if s.d.Raiser != nil {
		if _, err := s.d.Raiser.Raise(ctx, tx.Pgx(), reflexdomain.Signal{
			Org: org, Source: reflexdomain.SourceAutomation, RuleID: RuleLoop,
			Title:    "Automation trigger loop stopped",
			Summary:  fmt.Sprintf("Automation %s was triggered by work it is already upstream of (depth %d); the trigger was refused and the automation paused.", a.Name, lin.Depth),
			Severity: reflexdomain.SeverityMedium, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved,
			Subjects: subjects, GroupKey: "trigger_root:" + root.String(), DedupeKey: RuleLoop + ":" + root.String(),
			OccurredAt: now,
		}); err != nil {
			return fmt.Errorf("triggers: loop signal: %w", err)
		}
	}
	if err := s.failure(ctx, tx, reflexdomain.Failure{
		Org: org, Kind: FailureLoopStopped, DedupeKey: FailureLoopStopped + ":" + root.String(),
		Summary:  fmt.Sprintf("A chain of automations looped back to %s and was stopped; %s is paused.", a.Name, a.Name),
		NextStep: "Change the trigger or its `where` so the automation's own work cannot start it again, then resume it.",
		Scope:    subjects[:1], Owner: &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: a.Owner.String()},
	}); err != nil {
		return err
	}
	return s.audit(ctx, tx, "automation.trigger_refused", a.ID, out.Trigger, map[string]string{
		"state": string(out.State), "reason": out.Reason, "root": root.String(), "depth": fmt.Sprint(lin.Depth),
	})
}

func (s *Service) limit(ctx context.Context, tx db.TenantTx, c Candidate, out Outcome, now time.Time) error {
	q := dbq.New(tx)
	org, a := tx.OrgID(), c.Automation
	hour := now.UTC().Truncate(time.Hour)
	earlier, err := q.CountRefusalsSince(ctx, dbq.CountRefusalsSinceParams{
		OrgID: org, State: string(StateRefusedLimit), ExceptID: out.Trigger, AutomationID: &a.ID, Since: hour,
	})
	if err != nil || earlier > 0 {
		return err
	}
	if err := s.failure(ctx, tx, reflexdomain.Failure{
		Org: org, Kind: FailureHourlyCap, DedupeKey: FailureHourlyCap + ":" + a.ID.String() + ":" + hour.Format(time.RFC3339),
		Summary: fmt.Sprintf("Automation %s reached its limit of %d executions an hour; further triggers this hour are refused.",
			a.Name, a.Def.Limits.PerHourOrDefault()),
		NextStep: "Check what is triggering it so often; raise limits.per_hour in a new version only if the rate is expected.",
		Scope:    []reflexdomain.Subject{{Type: reflexdomain.SubjectAutomation, ID: a.ID.String()}},
		Owner:    &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: a.Owner.String()},
	}); err != nil {
		return err
	}
	return s.audit(ctx, tx, "automation.trigger_refused", a.ID, out.Trigger, map[string]string{
		"state": string(out.State), "reason": out.Reason, "hour": hour.Format(time.RFC3339),
	})
}

func (s *Service) failure(ctx context.Context, tx db.TenantTx, f reflexdomain.Failure) error {
	if s.d.Failures == nil {
		return nil
	}
	if _, err := s.d.Failures.Report(ctx, tx.Pgx(), f); err != nil {
		return fmt.Errorf("triggers: owned failure: %w", err)
	}
	return nil
}

func (s *Service) audit(ctx context.Context, tx db.TenantTx, name string, automation, trigger ids.UUID, details map[string]string) error {
	d := map[string]string{"automation": automation.String(), "trigger": trigger.String()}
	maps.Copy(d, details)
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: Actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "automation_trigger", ID: trigger.String()}, Details: d,
	})
	return err
}

// FireInSavepoint fires c inside a savepoint: one candidate that fails
// (an engine error) is rolled back alone and reported, so a batch of
// events never stalls on it.
func (s *Service) FireInSavepoint(ctx context.Context, tx db.TenantTx, c Candidate) (Outcome, bool) {
	sp, err := tx.Pgx().Begin(ctx)
	if err != nil {
		s.d.Log.ErrorContext(ctx, "automations.trigger_savepoint", pclog.Err(err))
		return Outcome{}, false
	}
	stx, err := db.AdoptTenantTx(ctx, sp, tx.OrgID())
	if err == nil {
		var out Outcome
		if out, err = s.Fire(ctx, stx, c); err == nil {
			if err = sp.Commit(ctx); err == nil {
				return out, true
			}
		}
	}
	_ = sp.Rollback(ctx)
	s.d.Log.ErrorContext(ctx, "automations.trigger_failed", slog.String("automation", c.Automation.ID.String()),
		slog.String("kind", string(c.Kind)), pclog.Err(err))
	_ = s.failure(ctx, tx, reflexdomain.Failure{
		Org: tx.OrgID(), Kind: FailureTriggerError,
		DedupeKey: FailureTriggerError + ":" + c.Automation.ID.String(),
		Summary:   fmt.Sprintf("A %s trigger of automation %s could not be recorded.", c.Kind, c.Automation.Name),
		NextStep:  "Check the server log for automations.trigger_failed; the trigger was not started.",
		Scope:     []reflexdomain.Subject{{Type: reflexdomain.SubjectAutomation, ID: c.Automation.ID.String()}},
	})
	return Outcome{}, false
}

func nonNilMap[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// MaxParamsBytes is the stored parameters' bound (00141 CHECK).
const MaxParamsBytes = 4096

// paramsTooLarge reports parameters whose stored form exceeds the bound
// (D87 L3): the trigger is refused, never failed at insert.
func paramsTooLarge(p map[string]autodomain.Value) bool {
	b, err := json.Marshal(nonNilMap(p), json.Deterministic(true))
	return err != nil || len(b) > MaxParamsBytes
}
