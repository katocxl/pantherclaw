// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Definition document v1 (D2).
const (
	APIVersion = "automations.pantherclaw.dev/v1"
	DocKind    = "Automation"
	// MaxDefinitionBytes bounds the canonical JSON (jsonb ≤ 64 KiB).
	MaxDefinitionBytes = 64 << 10
	// MaxSteps bounds `do`.
	MaxSteps = 20
	// MaxParams bounds a trigger's declared parameters.
	MaxParams = 16
	// MaxConditions bounds `if`.
	MaxConditions = 10
)

// ErrInvalid reports a definition that cannot be decoded strictly. Semantic
// problems are Findings (Validate), not errors.
var ErrInvalid = errors.New("automation: invalid definition")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalid}, args...)...)
}

// Definition is one automation version's document (D2). Every field is
// part of the reviewed digest. The work kind is `work_kind` because `kind`
// names the document type. The automation's name and owner live on its
// row, not here (D68), so changing the owner never changes a digest.
type Definition struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Purpose    string   `json:"purpose"`
	WorkKind   WorkKind `json:"work_kind"`
	// ReviewBy is a date (YYYY-MM-DD, UTC); required when the version has a
	// ceiling or an effectful platform scope.
	ReviewBy  Date           `json:"review_by,omitzero"`
	When      When           `json:"when"`
	If        []string       `json:"if,omitzero"`
	Authority Authority      `json:"authority"`
	Do        []StepSpec     `json:"do"`
	IfFails   *IfFails       `json:"if_fails,omitzero"`
	Finish    []Finish       `json:"finish_when"`
	Limits    Limits         `json:"limits,omitzero"`
	Paused    PausedTriggers `json:"paused_triggers,omitzero"`
	QueueMax  int            `json:"queue_max,omitzero"`
	QueueTTL  Duration       `json:"queue_ttl,omitzero"`
}

// When is the trigger section: exactly one kind, plus optional dedupe and
// active window (D2).
type When struct {
	Schedule  *Schedule      `json:"schedule,omitzero"`
	Event     *EventWhen     `json:"event,omitzero"`
	Inbound   *InboundWhen   `json:"inbound,omitzero"`
	Condition *ConditionWhen `json:"condition,omitzero"`
	Threshold *ThresholdWhen `json:"threshold,omitzero"`
	Manual    *ManualWhen    `json:"manual,omitzero"`
	Dedupe    *Dedupe        `json:"dedupe,omitzero"`
	Window    *ActiveWindow  `json:"window,omitzero"`
}

// Kind returns the trigger kind, or "" when none or several are set.
func (w When) Kind() TriggerKind {
	var k TriggerKind
	n := 0
	for _, c := range []struct {
		set  bool
		kind TriggerKind
	}{
		{w.Schedule != nil, TriggerSchedule},
		{w.Event != nil, TriggerEvent},
		{w.Inbound != nil, TriggerInbound},
		{w.Condition != nil, TriggerCondition},
		{w.Threshold != nil, TriggerThreshold},
		{w.Manual != nil, TriggerManual},
	} {
		if c.set {
			k, n = c.kind, n+1
		}
	}
	if n != 1 {
		return ""
	}
	return k
}

// Params returns the trigger's declared parameters (nil for schedules and
// thresholds, which have none).
func (w When) Params() map[string]ParamSpec {
	switch {
	case w.Event != nil:
		return w.Event.Params
	case w.Inbound != nil:
		return w.Inbound.Params
	case w.Condition != nil:
		return w.Condition.Params
	case w.Manual != nil:
		return w.Manual.Params
	}
	return nil
}

// Schedule fires on a five-field cron in an IANA zone (D2, D17).
type Schedule struct {
	Cron          string   `json:"cron"`
	Timezone      string   `json:"timezone"`
	Missed        string   `json:"missed,omitzero"`          // SKIP (default) | CATCH_UP
	CatchUpWindow Duration `json:"catch_up_window,omitzero"` // ≤ 24h, default 1h
	DSTGap        string   `json:"dst_gap,omitzero"`         // SKIP (default) | SHIFT
	Overlap       string   `json:"overlap,omitzero"`         // FORBID (default) | ALLOW
}

// Schedule option values.
const (
	MissedSkip    = "SKIP"
	MissedCatchUp = "CATCH_UP"
	DSTSkip       = "SKIP"
	DSTShift      = "SHIFT"
	OverlapForbid = "FORBID"
	OverlapAllow  = "ALLOW"
)

// EventWhen fires on a platform event of the D18 vocabulary.
type EventWhen struct {
	On     string               `json:"on"`
	Where  string               `json:"where,omitzero"`
	Params map[string]ParamSpec `json:"params,omitzero"`
}

// InboundWhen fires on a signed inbound event of one source and type.
type InboundWhen struct {
	Source RefID                `json:"source"`
	Type   string               `json:"type"`
	Params map[string]ParamSpec `json:"params,omitzero"`
}

// ConditionWhen fires once per episode a D19 probe holds for `for`.
type ConditionWhen struct {
	Probe  string               `json:"probe"`
	Where  string               `json:"where,omitzero"`
	For    Duration             `json:"for"`
	Params map[string]ParamSpec `json:"params,omitzero"`
}

// ThresholdWhen fires when matching events reach a count in a window.
type ThresholdWhen struct {
	On      string   `json:"on"`
	Where   string   `json:"where,omitzero"`
	GroupBy string   `json:"group_by,omitzero"` // agent | connection | operation | none
	Over    Duration `json:"over"`
	AtLeast int      `json:"at_least"`
}

// ManualWhen is started by a person (D20).
type ManualWhen struct {
	Params map[string]ParamSpec `json:"params,omitzero"`
	StepUp bool                 `json:"step_up,omitzero"`
}

// Dedupe declares a parameter key and window (≤ 30 d) beyond the trigger's
// own dedupe key (D23).
type Dedupe struct {
	Key    string   `json:"key"`
	Window Duration `json:"window"`
}

// ActiveWindow limits when triggers are accepted.
type ActiveWindow struct {
	From time.Time `json:"from,omitzero"`
	To   time.Time `json:"to,omitzero"`
}

// ParamType is a declared parameter's type.
type ParamType string

// Parameter types.
const (
	ParamString  ParamType = "string"
	ParamInt     ParamType = "int"
	ParamDecimal ParamType = "decimal"
	ParamEnum    ParamType = "enum"
	ParamUUID    ParamType = "uuid"
	ParamBool    ParamType = "bool"
)

// ParamSpec declares one typed, bounded trigger parameter (D2, HR-276).
type ParamSpec struct {
	// From is where the value comes from: an RFC 6901 JSON Pointer into an
	// inbound body, or a field path of the event, probe subject or form.
	From     string    `json:"from,omitzero"`
	Type     ParamType `json:"type"`
	Pattern  string    `json:"pattern,omitzero"` // RE2, anchored, ≤ 200
	MaxLen   int       `json:"max_len,omitzero"` // ≤ 256, default 64
	Min      string    `json:"min,omitzero"`     // int or decimal bound
	Max      string    `json:"max,omitzero"`
	Values   []string  `json:"values,omitzero"`   // enum, ≤ 50
	Required *bool     `json:"required,omitzero"` // default true
}

// IsRequired reports whether the parameter must be present (default true).
func (p ParamSpec) IsRequired() bool { return p.Required == nil || *p.Required }

// Authority is what the version may do (D2).
type Authority struct {
	// Principal is "self" (the automation's identity) or "user:<uuid>" (a
	// person who must be one of the enabling confirmers).
	Principal    string          `json:"principal"`
	Ceiling      *Ceiling        `json:"ceiling,omitzero"`
	Platform     []PlatformScope `json:"platform,omitzero"`
	Destinations []RefID         `json:"destinations,omitzero"`
	// Revocable is whose grants revoke_grant (TRIGGER_GRANT,
	// CEILING_AGENTS) and contain (REVOKE_GRANT) may revoke (D65).
	Revocable *AgentScope `json:"revocable,omitzero"`
}

// AgentScope names agents by id, or every agent of the org: exactly one
// of the two (D65 authority.revocable, D85 build_digest evidence).
type AgentScope struct {
	Agents []RefID `json:"agents,omitzero"`
	All    bool    `json:"all,omitzero"`
}

// Valid reports whether exactly one of Agents and All is set.
func (s AgentScope) Valid() bool { return (len(s.Agents) > 0) != s.All }

// Covers reports whether the scope includes the agent.
func (s AgentScope) Covers(agent RefID) bool { return s.All || slices.Contains(s.Agents, agent) }

// PrincipalSelf is the automation's own execution identity.
const PrincipalSelf = "self"

// PrincipalUser returns the user named by a "user:<uuid>" principal.
func (a Authority) PrincipalUser() (RefID, bool) {
	s, ok := strings.CutPrefix(a.Principal, "user:")
	if !ok {
		return RefID{}, false
	}
	var r RefID
	if err := r.UnmarshalText([]byte(s)); err != nil {
		return RefID{}, false
	}
	return r, true
}

// PlatformScope lists one platform step kind this version may use and the
// scopes it may touch (D3 column "scope").
type PlatformScope struct {
	Step   string   `json:"step"`
	Scopes []string `json:"scopes,omitzero"`
}

// Ceiling bounds every grant an execution may issue (D2, F1, D9). Its
// agents are always an explicit list (D55): a fleet cohort only narrows a
// COHORT rollout, never the ceiling.
type Ceiling struct {
	Agents       []RefID               `json:"agents,omitzero"`
	Bounds       gdomain.Bounds        `json:"bounds"`
	Requirements []gdomain.Requirement `json:"requirements,omitzero"`
	PerGrant     PerGrant              `json:"per_grant"`
	PerDay       PerDay                `json:"per_day"`
	Delegation   CeilingDelegation     `json:"delegation,omitzero"`
	Concurrency  int                   `json:"concurrency,omitzero"` // 1..10, default 1
}

// PerGrant bounds each issued grant.
type PerGrant struct {
	TTL            Duration       `json:"ttl"`
	Limits         gdomain.Limits `json:"limits,omitzero"`
	MinAttestation int            `json:"min_attestation,omitzero"`
}

// PerDay caps an automation's issuance per UTC day.
type PerDay struct {
	Grants int     `json:"grants"`
	Runs   int     `json:"runs"`
	Budget []Money `json:"budget,omitzero"`
}

// Money is an amount in one currency (decimal string).
type Money struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"`
}

// CeilingDelegation bounds what an issued grant may delegate.
type CeilingDelegation struct {
	Depth       int `json:"depth,omitzero"`        // 0..1
	MaxChildren int `json:"max_children,omitzero"` // 0..10
}

// ConcurrencyOrDefault is the ceiling's concurrency, 1 when unset.
func (c Ceiling) ConcurrencyOrDefault() int {
	if c.Concurrency == 0 {
		return 1
	}
	return c.Concurrency
}

// StepSpec is one entry of `do` (D2). With holds the kind's schema (D3),
// decoded strictly by DecodeWith and stored canonically.
type StepSpec struct {
	ID        string         `json:"id"`
	Step      string         `json:"step"`
	With      jsontext.Value `json:"with,omitzero"`
	When      string         `json:"when,omitzero"`
	Timeout   Duration       `json:"timeout,omitzero"`
	Retry     *Retry         `json:"retry,omitzero"`
	OnFailure OnFailure      `json:"on_failure,omitzero"`
}

// Retry declares attempts and backoff for a retry-safe kind.
type Retry struct {
	MaxAttempts int     `json:"max_attempts"`
	Backoff     Backoff `json:"backoff,omitzero"`
}

// Backoff bounds the delay between attempts (min ≥ 10s, max ≤ 1h).
type Backoff struct {
	Min Duration `json:"min,omitzero"`
	Max Duration `json:"max,omitzero"`
}

// IfFails is the execution-level failure section.
type IfFails struct {
	Default    OnFailure  `json:"default,omitzero"`
	Compensate []StepSpec `json:"compensate,omitzero"`
	Notify     []string   `json:"notify,omitzero"` // OWNER
}

// Finish is one finish_when entry.
type Finish struct {
	Step      string          `json:"step"`
	Condition FinishCondition `json:"condition"`
}

// Limits bound an execution's life and the trigger rate.
type Limits struct {
	Deadline Duration `json:"deadline,omitzero"` // ≤ 7d, default 24h
	PerHour  int      `json:"per_hour,omitzero"` // 1..600, default 60
}

// Defaults (D2).
const (
	DefaultDeadline      = 24 * time.Hour
	DefaultPerHour       = 60
	DefaultCatchUpWindow = time.Hour
	DefaultClaimWithin   = 15 * time.Minute
)

// DeadlineOrDefault is the declared deadline, 24h when unset.
func (l Limits) DeadlineOrDefault() time.Duration {
	if l.Deadline == 0 {
		return DefaultDeadline
	}
	return time.Duration(l.Deadline)
}

// PerHourOrDefault is the declared hourly cap, 60 when unset.
func (l Limits) PerHourOrDefault() int {
	if l.PerHour == 0 {
		return DefaultPerHour
	}
	return l.PerHour
}

// Step returns the step with id, or nil.
func (d *Definition) Step(id string) *StepSpec {
	for i := range d.Do {
		if d.Do[i].ID == id {
			return &d.Do[i]
		}
	}
	return nil
}

// Parse decodes a definition authored as YAML or JSON: strictly (unknown
// fields refused, one document, no anchors, tags or nulls), every step's
// `with` decoded into its kind's schema, and stored canonically. Semantic
// checks are Validate's.
func Parse(raw []byte) (*Definition, error) {
	doc := bytes.TrimSpace(raw)
	if len(doc) == 0 || len(doc) > 4*MaxDefinitionBytes {
		return nil, invalid("size %d outside 1..%d bytes", len(raw), 4*MaxDefinitionBytes)
	}
	if doc[0] != '{' {
		j, err := yamlToJSON(doc)
		if err != nil {
			return nil, err
		}
		doc = j
	}
	var d Definition
	if err := json.Unmarshal(doc, &d, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("%v", err)
	}
	if d.APIVersion != APIVersion || d.Kind != DocKind {
		return nil, invalid("apiVersion must be %q and kind %q", APIVersion, DocKind)
	}
	if err := d.canonicalizeWith(); err != nil {
		return nil, err
	}
	c, err := d.Canonical()
	if err != nil {
		return nil, err
	}
	if len(c) > MaxDefinitionBytes {
		return nil, invalid("the definition is %d bytes; at most %d", len(c), MaxDefinitionBytes)
	}
	return &d, nil
}

// canonicalizeWith decodes every step's `with` into its kind's schema
// (unknown kinds are left for Validate's UNSUPPORTED_CAPABILITY) and
// re-encodes it deterministically.
func (d *Definition) canonicalizeWith() error {
	fix := func(specs []StepSpec, at string) error {
		for i := range specs {
			s := &specs[i]
			spec, ok := Catalog[s.Step]
			if !ok {
				continue
			}
			w, err := spec.DecodeWith(s.With)
			if err != nil {
				return invalid("%s[%d] (%s).with: %v", at, i, s.ID, err)
			}
			b, err := json.Marshal(w, json.Deterministic(true))
			if err != nil {
				return invalid("%s[%d].with: %v", at, i, err)
			}
			if string(b) == "{}" {
				b = nil
			}
			s.With = b
		}
		return nil
	}
	if err := fix(d.Do, "do"); err != nil {
		return err
	}
	if d.IfFails != nil {
		return fix(d.IfFails.Compensate, "if_fails.compensate")
	}
	return nil
}

// Canonical is the stored form: deterministic JSON of the Go struct.
func (d *Definition) Canonical() ([]byte, error) {
	b, err := json.Marshal(d, json.Deterministic(true))
	if err != nil {
		return nil, invalid("%v", err)
	}
	return b, nil
}

// Digest is SHA-256 of the canonical JSON (D2).
func (d *Definition) Digest() ([]byte, error) {
	c, err := d.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return sum[:], nil
}

// DecodeWith decodes the `with` of the step at spec into its kind's schema.
func (s StepSpec) DecodeWith() (any, error) {
	k, ok := Catalog[s.Step]
	if !ok {
		return nil, invalid("unknown step kind %q", s.Step)
	}
	return k.DecodeWith(s.With)
}

// Duration is a JSON duration: Go syntax ("90s", "15m", "24h") or whole
// days ("7d"). It marshals as days when a whole number of days.
type Duration time.Duration

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) {
	t := time.Duration(d)
	if t > 0 && t%(24*time.Hour) == 0 {
		return []byte(strconv.FormatInt(int64(t/(24*time.Hour)), 10) + "d"), nil
	}
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	s := string(b)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		v, err := strconv.Atoi(n)
		if err != nil || v < 1 || v > 3650 || strconv.Itoa(v) != n {
			return invalid("duration %q: days are a whole number from 1 to 3650", s)
		}
		*d = Duration(time.Duration(v) * 24 * time.Hour)
		return nil
	}
	t, err := time.ParseDuration(s)
	if err != nil || t <= 0 {
		return invalid("duration %q: write it like 30s, 15m, 24h or 7d", s)
	}
	*d = Duration(t)
	return nil
}

// Date is a calendar date (YYYY-MM-DD), compared in UTC.
type Date struct{ t time.Time }

// NewDate returns the date of t in UTC.
func NewDate(t time.Time) Date {
	y, m, day := t.UTC().Date()
	return Date{t: time.Date(y, m, day, 0, 0, 0, 0, time.UTC)}
}

// Time is the start of the date (UTC).
func (d Date) Time() time.Time { return d.t }

// MarshalText implements encoding.TextMarshaler.
func (d Date) MarshalText() ([]byte, error) { return []byte(d.t.UTC().Format(time.DateOnly)), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Date) UnmarshalText(b []byte) error {
	t, err := time.Parse(time.DateOnly, string(b))
	if err != nil {
		return invalid("date %q: write it YYYY-MM-DD", string(b))
	}
	d.t = t
	return nil
}

// IsZero reports whether the date is unset.
func (d Date) IsZero() bool { return d.t.IsZero() }

// End is the first instant after the date (UTC): a review date holds
// through its whole day.
func (d Date) End() time.Time { return d.t.UTC().AddDate(0, 0, 1) }

// NotWiderThan reports whether c grants nothing prev did not (D91): agents
// and bounds inside prev's, requirements, minimum attestation and every
// per-grant limit kept or tightened, and every cap no higher.
func (c *Ceiling) NotWiderThan(prev *Ceiling) bool {
	if c == nil || prev == nil {
		return c == nil
	}
	for _, a := range c.Agents {
		if !slices.Contains(prev.Agents, a) {
			return false
		}
	}
	if c.Bounds.Within(prev.Bounds) != nil {
		return false
	}
	for _, r := range prev.Requirements {
		if !slices.ContainsFunc(c.Requirements, func(x gdomain.Requirement) bool { return reflectEqualJSON(x, r) }) {
			return false
		}
	}
	if c.PerGrant.TTL > prev.PerGrant.TTL || c.PerGrant.MinAttestation < prev.PerGrant.MinAttestation {
		return false
	}
	if len(c.PerGrant.Limits.Budgets) != len(prev.PerGrant.Limits.Budgets) ||
		len(c.PerGrant.Limits.Counters) != len(prev.PerGrant.Limits.Counters) {
		return false
	}
	if _, err := gdomain.NarrowLimits(prev.PerGrant.Limits, c.PerGrant.Limits); err != nil {
		return false
	}
	if c.PerDay.Grants > prev.PerDay.Grants || c.PerDay.Runs > prev.PerDay.Runs ||
		c.ConcurrencyOrDefault() > prev.ConcurrencyOrDefault() ||
		c.Delegation.Depth > prev.Delegation.Depth || c.Delegation.MaxChildren > prev.Delegation.MaxChildren {
		return false
	}
	for _, m := range c.PerDay.Budget {
		i := slices.IndexFunc(prev.PerDay.Budget, func(p Money) bool { return p.Currency == m.Currency })
		if i < 0 {
			return false
		}
		cur, err1 := money.Parse(m.Amount)
		was, err2 := money.Parse(prev.PerDay.Budget[i].Amount)
		if err1 != nil || err2 != nil || cur.Cmp(was) > 0 {
			return false
		}
	}
	return true // a currency without a daily budget is never spent
}

func reflectEqualJSON(a, b any) bool {
	x, err1 := json.Marshal(a, json.Deterministic(true))
	y, err2 := json.Marshal(b, json.Deterministic(true))
	return err1 == nil && err2 == nil && bytes.Equal(x, y)
}
