// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/cron"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// Historical simulation (D35, F741, F742, F745): the version's trigger
// replayed over past history, at most 30 days, with what each would-be
// execution's steps would do today, what could not be evaluated, and
// forecasts. It reads history and writes nothing but its own row (HR-288).

// MaxSimulationRange bounds a simulation.
const MaxSimulationRange = 30 * 24 * time.Hour

// maxSamples bounds the sample executions.
const maxSamples = 50

// Missing-context codes (UNEVALUABLE, HR-288).
const (
	MissingProbe           = "CONDITION_PROBE"       // a probe whose history is not kept
	MissingEvent           = "EVENT_NOT_IN_FEED"     // a vocabulary name the feed cannot replay
	MissingWhere           = "WHERE_UNEVALUABLE"     // a `where` that failed to evaluate
	MissingIf              = "IF_UNEVALUABLE"        // `if` conditions over parameters not in history
	MissingParams          = "PARAMS_UNEVALUABLE"    // inbound bodies are never stored
	MissingReceipts        = "RECEIPTS_NOT_KEPT"     // days before inbound receipts are kept
	MissingManual          = "MANUAL_NOT_REPLAYED"   // manual starts are not history
	MissingFeedTruncated   = "FEED_TRUNCATED"        // more history than one simulation reads
	MissingIssuancePreview = "ISSUANCE_CEILING_ONLY" // launch decisions checked against the ceiling only
)

// Receipt is a past inbound delivery (types only; bodies are never kept).
type Receipt struct {
	Source ids.UUID
	Type   string
	At     time.Time
}

// GrantExpiry is a grant's expiry, for the grant.expiring probe.
type GrantExpiry struct {
	Grant, Agent ids.UUID
	Principal    string
	TaskRef      string
	ExpiresAt    time.Time
}

// History is what a simulation reads.
type History struct {
	Events          []feed.Event
	EventsTruncated bool
	Receipts        []Receipt
	// ReceiptsFrom is the oldest time receipts are kept for.
	ReceiptsFrom time.Time
	Grants       []GrantExpiry
	// Approvers is how many people may decide the version's gates today.
	Approvers int
}

// SimDay is one day's would-be triggers.
type SimDay struct {
	Day         string `json:"day"`
	WouldFire   int    `json:"would_fire"`
	Unevaluable int    `json:"unevaluable,omitzero"`
}

// SimStep is one prospective step of a sample.
type SimStep struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitzero"`
}

// Sample is one would-be execution.
type Sample struct {
	At        time.Time `json:"at"`
	Kind      string    `json:"kind"`
	SourceRef string    `json:"source_ref"`
	Steps     []SimStep `json:"steps"`
}

// Budget forecast of one currency.
type BudgetForecast struct {
	Currency string `json:"currency"`
	Max      string `json:"max_per_day"`
	Expected string `json:"expected_per_day"`
}

// Forecast are per-day expectations.
type Forecast struct {
	ExecutionsPerDay  float64          `json:"executions_per_day"`
	GatesPerDay       float64          `json:"gates_per_day"`
	EligibleApprovers int              `json:"eligible_approvers"`
	GrantsPerDay      float64          `json:"grants_per_day"`
	Budget            []BudgetForecast `json:"budget,omitzero"`
}

// SimResults are a simulation's results.
type SimResults struct {
	Days     []SimDay       `json:"days"`
	Samples  []Sample       `json:"samples"`
	Missing  map[string]int `json:"missing_context,omitzero"`
	Forecast Forecast       `json:"forecast"`
	// Refused counts would-be triggers the version's own limits refuse.
	Refused map[string]int `json:"refused,omitzero"`
}

// fire is one would-be trigger.
type fire struct {
	at  time.Time
	ref string
}

// Replay simulates def over [from, to) on the history.
func Replay(ctx context.Context, def *autodomain.Definition, h History, from, to time.Time) SimResults {
	out := SimResults{Missing: map[string]int{}, Refused: map[string]int{}}
	var fires []fire
	miss := func(code string, n int) { out.Missing[code] += n }
	if h.EventsTruncated {
		miss(MissingFeedTruncated, 1)
	}
	w := def.When
	switch {
	case w.Schedule != nil:
		fires = scheduleFires(w.Schedule, from, to, miss)
	case w.Event != nil:
		fires = eventFires(ctx, w.Event.On, w.Event.Where, h.Events, from, to, miss)
	case w.Threshold != nil:
		fires = thresholdFires(ctx, w.Threshold, h.Events, from, to, miss)
	case w.Condition != nil:
		fires = conditionFires(ctx, w.Condition, h.Grants, from, to, miss)
	case w.Inbound != nil:
		for _, r := range h.Receipts {
			if r.Source == w.Inbound.Source.UUID() && r.Type == w.Inbound.Type && !r.At.Before(from) && r.At.Before(to) {
				fires = append(fires, fire{at: r.At, ref: "inbound:" + r.Type})
			}
		}
		if len(fires) > 0 && len(w.Inbound.Params) > 0 {
			miss(MissingParams, len(fires))
		}
		if h.ReceiptsFrom.After(from) {
			miss(MissingReceipts, int(math.Ceil(h.ReceiptsFrom.Sub(from).Hours()/24)))
		}
	case w.Manual != nil:
		miss(MissingManual, 1)
	}
	if len(def.If) > 0 && len(fires) > 0 && w.Schedule == nil {
		miss(MissingIf, len(fires))
	}
	slices.SortFunc(fires, func(a, b fire) int { return a.at.Compare(b.at) })
	fires = limitHourly(def, fires, out.Refused)

	byDay := map[string]*SimDay{}
	for d := from.UTC().Truncate(24 * time.Hour); d.Before(to); d = d.Add(24 * time.Hour) {
		day := d.Format(time.DateOnly)
		byDay[day] = &SimDay{Day: day}
		out.Days = append(out.Days, SimDay{Day: day})
	}
	grantsByDay := map[string]int{}
	launches := 0
	for _, s := range def.Do {
		if s.Step == autodomain.KindLaunchRun {
			launches++
		}
	}
	every := max(1, len(fires)/maxSamples)
	for i, f := range fires {
		day := f.at.UTC().Format(time.DateOnly)
		if d, ok := byDay[day]; ok {
			d.WouldFire++
		}
		steps := prospective(def, grantsByDay, day)
		if i%every == 0 && len(out.Samples) < maxSamples {
			out.Samples = append(out.Samples, Sample{At: f.at, Kind: string(w.Kind()), SourceRef: f.ref, Steps: steps})
		}
	}
	for i := range out.Days {
		out.Days[i] = *byDay[out.Days[i].Day]
	}
	if launches > 0 && len(fires) > 0 {
		miss(MissingIssuancePreview, len(fires))
	}
	out.Forecast = forecast(def, len(fires), to.Sub(from), h.Approvers, grantsByDay)
	return out
}

func scheduleFires(s *autodomain.Schedule, from, to time.Time, miss func(string, int)) []fire {
	spec, err := cron.Parse(s.Cron)
	if err != nil {
		miss("SCHEDULE_INVALID", 1)
		return nil
	}
	loc, err := cron.LoadZone(s.Timezone)
	if err != nil {
		miss("SCHEDULE_INVALID", 1)
		return nil
	}
	gap := cron.GapSkip
	if s.DSTGap == "SHIFT" {
		gap = cron.GapShift
	}
	var out []fire
	after := from.Add(-time.Nanosecond)
	for len(out) < 100000 {
		o, ok := spec.Next(after, loc, gap)
		if !ok || !o.At.Before(to) {
			break
		}
		after = o.At
		if o.Fires {
			out = append(out, fire{at: o.At, ref: "schedule:" + o.Scheduled})
		}
	}
	return out
}

func eventFires(ctx context.Context, on, where string, events []feed.Event, from, to time.Time, miss func(string, int)) []fire {
	if on == triggers.VocabCaseClosed || on == triggers.VocabAgentDiscovered {
		miss(MissingEvent+":"+on, 1)
		return nil
	}
	var out []fire
	for _, e := range events {
		if e.Test || e.OccurredAt.Before(from) || !e.OccurredAt.Before(to) || !triggers.Means(on, e, triggers.Facts{}) {
			continue
		}
		if where != "" {
			ok, err := triggers.MatchEvent(ctx, where, e)
			if err != nil {
				miss(MissingWhere, 1)
				continue
			}
			if !ok {
				continue
			}
		}
		out = append(out, fire{at: e.OccurredAt, ref: "event:" + e.ID.String()})
	}
	return out
}

// groupOf is a threshold event's group key.
func groupOf(by string, e feed.Event) string {
	switch by {
	case "agent":
		v, _ := e.Subject(reflexdomain.SubjectAgent)
		return v
	case "connection":
		v, _ := e.Subject(reflexdomain.SubjectConnection)
		return v
	case "operation":
		return e.Operation
	}
	return ""
}

func thresholdFires(ctx context.Context, t *autodomain.ThresholdWhen, events []feed.Event, from, to time.Time,
	miss func(string, int),
) []fire {
	over := t.Over.D()
	if over <= 0 || t.AtLeast < 1 {
		return nil
	}
	matched := eventFires(ctx, t.On, t.Where, events, from.Add(-over), to, miss)
	byEvent := map[string]feed.Event{}
	for _, e := range events {
		byEvent["event:"+e.ID.String()] = e
	}
	type bucket struct {
		group string
		start time.Time
	}
	counts, fired := map[bucket]int{}, map[bucket]bool{}
	var out []fire
	for _, f := range matched {
		b := bucket{group: groupOf(t.GroupBy, byEvent[f.ref]), start: f.at.UTC().Truncate(over)}
		counts[b]++
		if counts[b] >= t.AtLeast && !fired[b] && !f.at.Before(from) {
			fired[b] = true
			out = append(out, fire{at: f.at, ref: "threshold:" + b.group + ":" + b.start.Format(time.RFC3339)})
		}
	}
	return out
}

func conditionFires(ctx context.Context, c *autodomain.ConditionWhen, grants []GrantExpiry, from, to time.Time,
	miss func(string, int),
) []fire {
	if c.Probe != triggers.ProbeGrantExpiring {
		miss(MissingProbe+":"+c.Probe, 1)
		return nil
	}
	var out []fire
	for _, g := range grants {
		// Evaluate the probe hourly from the window's start (or 7 days
		// before the expiry) to the expiry; fire once the subject has held
		// for `for`.
		var since *time.Time
		begin, end := later(from, g.ExpiresAt.Add(-7*24*time.Hour)), earlier(to, g.ExpiresAt)
		for at := begin.Truncate(time.Hour); at.Before(end); at = at.Add(time.Hour) {
			s := triggers.ProbeSubject{Probe: c.Probe, Key: "grant:" + g.Grant.String(), Fields: map[string]string{
				"grant": g.Grant.String(), "agent": g.Agent.String(), "principal": g.Principal, "task_ref": g.TaskRef,
				"hours_left": strconv.Itoa(int(math.Floor(g.ExpiresAt.Sub(at).Hours()))),
			}}
			ok := true
			if c.Where != "" {
				var err error
				if ok, err = triggers.MatchSubject(ctx, c.Where, s); err != nil {
					miss(MissingWhere, 1)
					break
				}
			}
			if !ok {
				since = nil
				continue
			}
			if since == nil {
				t := at
				since = &t
			}
			if at.Sub(*since) >= c.For.D() {
				out = append(out, fire{at: at, ref: "condition:grant:" + g.Grant.String()})
				break
			}
		}
	}
	return out
}

// limitHourly refuses would-be triggers past the version's hourly cap
// (limits.per_hour, HR-278).
func limitHourly(def *autodomain.Definition, fires []fire, refused map[string]int) []fire {
	limit := def.Limits.PerHourOrDefault()
	perHour := map[time.Time]int{}
	var out []fire
	for _, f := range fires {
		h := f.at.UTC().Truncate(time.Hour)
		if perHour[h] >= limit {
			refused["REFUSED_LIMIT"]++
			continue
		}
		perHour[h]++
		out = append(out, f)
	}
	return out
}

// prospective lists what a would-be execution's steps would do: a launch
// is checked against the ceiling and its per-day grant cap (the issuance
// preview, D9 DryRun, takes its place once wired); effectful steps would
// run; gates wait for a person.
func prospective(def *autodomain.Definition, grantsByDay map[string]int, day string) []SimStep {
	var out []SimStep
	for _, s := range def.Do {
		st := SimStep{ID: s.ID, Kind: s.Step, Decision: "WOULD_RUN"}
		spec := autodomain.Catalog[s.Step]
		switch {
		case s.Step == autodomain.KindLaunchRun:
			st.Decision, st.Reason = launchDecision(def, s, grantsByDay, day)
		case s.Step == autodomain.KindGate:
			st.Decision = "GATE"
		case spec.Wait:
			st.Decision = "WAIT"
		}
		if s.When != "" {
			st.Decision, st.Reason = "UNEVALUABLE", "GUARD"
		}
		out = append(out, st)
	}
	return out
}

func launchDecision(def *autodomain.Definition, s autodomain.StepSpec, grantsByDay map[string]int, day string) (string, string) {
	ce := def.Authority.Ceiling
	if ce == nil {
		return "REFUSED", "CEILING_MISSING"
	}
	w, err := s.DecodeWith()
	lw, ok := w.(*autodomain.LaunchRunWith)
	if err != nil || !ok {
		return "UNEVALUABLE", "WITH_INVALID"
	}
	if !slices.ContainsFunc(ce.Agents, func(a autodomain.RefID) bool { return a == lw.Agent }) {
		return "REFUSED", "OUTSIDE_CEILING"
	}
	if lw.Grant.Operations != nil && ce.Bounds.Operations != nil {
		if _, ok := lw.Grant.Operations.Within(*ce.Bounds.Operations); !ok {
			return "REFUSED", "OUTSIDE_CEILING"
		}
	}
	if ce.PerDay.Grants > 0 && grantsByDay[day] >= ce.PerDay.Grants {
		return "REFUSED", "USAGE_EXCEEDED"
	}
	grantsByDay[day]++
	return "ALLOWED", ""
}

func forecast(def *autodomain.Definition, fires int, span time.Duration, approvers int, grantsByDay map[string]int) Forecast {
	days := max(1, span.Hours()/24)
	f := Forecast{ExecutionsPerDay: round2(float64(fires) / days), EligibleApprovers: approvers}
	gates := 0
	for _, s := range def.Do {
		if s.Step == autodomain.KindGate {
			gates++
		}
	}
	f.GatesPerDay = round2(f.ExecutionsPerDay * float64(gates))
	total := 0
	for _, n := range grantsByDay {
		total += n
	}
	f.GrantsPerDay = round2(float64(total) / days)
	if ce := def.Authority.Ceiling; ce != nil {
		for _, b := range ce.PerDay.Budget {
			f.Budget = append(f.Budget, BudgetForecast{Currency: b.Currency, Max: b.Amount, Expected: expected(b, ce, f.GrantsPerDay)})
		}
	}
	return f
}

// expected is the expected spend per day: grants per day times the
// per-grant budget limit in the currency, at most the daily cap; unknown
// ("") when the per-grant limit names no budget in it.
func expected(b autodomain.Money, ce *autodomain.Ceiling, grantsPerDay float64) string {
	limit, err := strconv.ParseFloat(b.Amount, 64)
	if err != nil {
		return ""
	}
	per, ok := perGrantBudget(ce, b.Currency)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%.2f", math.Min(limit, per*grantsPerDay))
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// perGrantBudget is the per-grant budget limit in currency (the sum of the
// task budgets in it).
func perGrantBudget(ce *autodomain.Ceiling, currency string) (float64, bool) {
	total, found := 0.0, false
	for _, r := range ce.PerGrant.Limits.Budgets {
		if r.Currency != currency || r.Limit == "" {
			continue
		}
		v, err := strconv.ParseFloat(r.Limit, 64)
		if err != nil {
			return 0, false
		}
		total, found = total+v, true
	}
	return total, found
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
