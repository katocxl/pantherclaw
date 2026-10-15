// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rules parses, validates and compiles detection rules (G0 M10 D9).
// A rule is a YAML document: what it is (id, version, title, severity,
// attention, basis, ATLAS and OWASP mappings, edition), which feed events
// it reads (on), a CEL condition over one event (match), at most one
// stateful detector (window, first_seen or sequence), how its alerts group
// and its tests. Rules only raise signals; nothing in a rule can act.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Editions a rule runs in.
const (
	EditionCommunity = "community"
	EditionBusiness  = "business"
)

// Groups an alert can group by (F603).
var groups = []string{"run", "agent", "principal", "grant", "target", "connection"}

// Bounds of a rule (D9).
const (
	MaxWindow       = 24 * time.Hour
	MaxHorizon      = 90 * 24 * time.Hour
	MaxWithin       = 24 * time.Hour
	MaxOn           = 16
	MaxTests        = 32
	MaxTestEvents   = 64
	MaxGroupBy      = 4
	MaxWindowCount  = 100_000
	MinSequence     = 2
	MaxSequence     = 4
	MaxDescription  = 2000
	MaxRuleFileSize = rtdomain.MaxFileBytes
)

// ErrInvalid reports a rule that does not parse or validate.
var ErrInvalid = errors.New("detection: invalid rule")

func invalid(id, format string, a ...any) error {
	if id != "" {
		return fmt.Errorf("%w: %s: %s", ErrInvalid, id, fmt.Sprintf(format, a...))
	}
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Rule is one detection rule.
type Rule struct {
	ID          string                 `json:"id"`
	Version     string                 `json:"version"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    reflexdomain.Severity  `json:"severity"`
	Attention   reflexdomain.Attention `json:"attention"`
	Basis       reflexdomain.Basis     `json:"basis"`
	ATLAS       []string               `json:"atlas"`
	OWASP       []string               `json:"owasp"`
	Edition     string                 `json:"edition"`
	On          []string               `json:"on"`
	Match       string                 `json:"match,omitzero"`
	Window      *Window                `json:"window,omitzero"`
	FirstSeen   *FirstSeen             `json:"first_seen,omitzero"`
	Sequence    *Sequence              `json:"sequence,omitzero"`
	Group       string                 `json:"group,omitzero"`
	Tests       []Test                 `json:"tests"`
}

// Window counts matching events per group over a sliding duration; it
// fires when the count (or the count of distinct values of Distinct)
// reaches Count.
type Window struct {
	Duration string   `json:"duration"`
	GroupBy  []string `json:"group_by"`
	Count    int      `json:"count"`
	Distinct string   `json:"distinct,omitzero"`
}

// FirstSeen fires the first time a key is seen within Horizon.
type FirstSeen struct {
	Keys    []string `json:"keys"`
	Horizon string   `json:"horizon"`
}

// Sequence fires when its steps match in order for one group within
// Within.
type Sequence struct {
	Steps   []Step   `json:"steps"`
	Within  string   `json:"within"`
	GroupBy []string `json:"group_by"`
}

// Step is one step of a sequence.
type Step struct {
	On    []string `json:"on"`
	Match string   `json:"match,omitzero"`
}

// Test is a fixture: events in order and whether the rule fires on them.
type Test struct {
	Name   string      `json:"name"`
	Events []TestEvent `json:"events"`
	Fires  bool        `json:"fires"`
}

// TestEvent is a feed event of a test; At is its offset from the test's
// start (a Go duration, "0s" when empty).
type TestEvent struct {
	At               string            `json:"at,omitzero"`
	Kind             string            `json:"kind"`
	ActorType        string            `json:"actor_type,omitzero"`
	ActorID          string            `json:"actor_id,omitzero"`
	Decision         string            `json:"decision,omitzero"`
	Reason           string            `json:"reason,omitzero"`
	Operation        string            `json:"operation,omitzero"`
	Mode             string            `json:"mode,omitzero"`
	Outcome          string            `json:"outcome,omitzero"`
	Environment      string            `json:"environment,omitzero"`
	DestinationClass string            `json:"destination_class,omitzero"`
	Subjects         map[string]string `json:"subjects,omitzero"`
	Attrs            map[string]string `json:"attrs,omitzero"`
}

// Parse decodes one YAML rule strictly (one document, no anchors, aliases,
// tags or unknown fields) and validates it.
func Parse(raw []byte) (*Rule, error) {
	doc, err := rtdomain.ToJSON(raw)
	if err != nil {
		return nil, invalid("", "%v", err)
	}
	var r Rule
	if err := json.Unmarshal(doc, &r, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("", "%v", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Digest is the hex SHA-256 of a rule file's bytes.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var (
	builtinID  = regexp.MustCompile(`^pc\.[a-z][a-z0-9_]{0,62}(\.[a-z0-9_]{1,63}){1,3}$`)
	customID   = regexp.MustCompile(`^org\.[a-z][a-z0-9_]{0,62}(\.[a-z0-9_]{1,63}){0,3}$`)
	versionRe  = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)
	kindRe     = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*(\.\*)?$`)
	atlasRe    = regexp.MustCompile(`^AML\.T[0-9]{4}(\.[0-9]{3})?$`)
	owaspRe    = regexp.MustCompile(`^ASI(0[1-9]|10)$`)
	fieldRe    = regexp.MustCompile(`^(kind|actor_type|actor_id|decision|reason|operation|mode|outcome|environment|destination_class|subjects\.[a-z_]+|attrs\.[a-z][a-z0-9_]{0,63})$`)
	subjectFld = regexp.MustCompile(`^subjects\.([a-z_]+)$`)
	testNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9 _.-]{0,79}$`)
	attrKeyRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Builtin reports whether the rule id is a built-in one (pc.*).
func (r *Rule) Builtin() bool { return strings.HasPrefix(r.ID, "pc.") }

// Validate checks the rule against D9.
func (r *Rule) Validate() error {
	id := r.ID
	switch {
	case !builtinID.MatchString(id) && !customID.MatchString(id):
		return invalid("", "id %q must be pc.<area>.<name> or org.<slug>", id)
	case !versionRe.MatchString(r.Version):
		return invalid(id, "version must be a positive integer")
	case r.Title == "" || len(r.Title) > reflexdomain.MaxTitle:
		return invalid(id, "title 1..%d bytes", reflexdomain.MaxTitle)
	case r.Description == "" || len(r.Description) > MaxDescription:
		return invalid(id, "description 1..%d bytes", MaxDescription)
	case !r.Severity.Valid():
		return invalid(id, "unknown severity %q", r.Severity)
	case !r.Attention.Valid() || r.Attention == reflexdomain.AttentionTelemetry:
		return invalid(id, "attention must be LIVE, FINDING, ALERT, INCIDENT or PAGE")
	case !r.Basis.Valid():
		return invalid(id, "unknown basis %q", r.Basis)
	case r.Edition != EditionCommunity && r.Edition != EditionBusiness:
		return invalid(id, "edition must be community or business")
	case len(r.On) == 0 && r.Sequence == nil, len(r.On) > MaxOn:
		return invalid(id, "on lists 1..%d event kinds", MaxOn)
	case len(r.ATLAS) > reflexdomain.MaxMappings || len(r.OWASP) > reflexdomain.MaxMappings:
		return invalid(id, "at most %d mappings each", reflexdomain.MaxMappings)
	case r.Group != "" && !slices.Contains(groups, r.Group):
		return invalid(id, "group must be one of %v", groups)
	}
	for _, a := range r.ATLAS {
		if !atlasRe.MatchString(a) {
			return invalid(id, "ATLAS technique %q", a)
		}
	}
	for _, o := range r.OWASP {
		if !owaspRe.MatchString(o) {
			return invalid(id, "OWASP agentic risk %q", o)
		}
	}
	if err := checkKinds(id, r.On); err != nil {
		return err
	}
	detectors := 0
	if r.Window != nil {
		detectors++
		if err := r.Window.validate(id); err != nil {
			return err
		}
	}
	if r.FirstSeen != nil {
		detectors++
		if err := r.FirstSeen.validate(id); err != nil {
			return err
		}
	}
	if r.Sequence != nil {
		detectors++
		if len(r.On) != 0 || r.Match != "" {
			return invalid(id, "a sequence rule matches through its steps, not on and match")
		}
		if err := r.Sequence.validate(id); err != nil {
			return err
		}
	}
	if detectors > 1 {
		return invalid(id, "at most one of window, first_seen and sequence")
	}
	if !r.Builtin() {
		// Custom rules (F4): Business, alert-only, never PAGE (D13).
		if r.Edition != EditionBusiness {
			return invalid(id, "a custom rule's edition is business")
		}
		if r.Attention.AtLeast(reflexdomain.AttentionPage) {
			return invalid(id, "a custom rule raises at most INCIDENT")
		}
	}
	if len(r.Tests) > MaxTests {
		return invalid(id, "at most %d tests", MaxTests)
	}
	for _, t := range r.Tests {
		if !testNameRe.MatchString(t.Name) {
			return invalid(id, "test name %q", t.Name)
		}
		if len(t.Events) == 0 || len(t.Events) > MaxTestEvents {
			return invalid(id, "test %q holds 1..%d events", t.Name, MaxTestEvents)
		}
		for _, e := range t.Events {
			if !kindRe.MatchString(e.Kind) || strings.HasSuffix(e.Kind, ".*") {
				return invalid(id, "test %q: event kind %q", t.Name, e.Kind)
			}
			if e.At != "" {
				if d, err := time.ParseDuration(e.At); err != nil || d < 0 || d > MaxHorizon {
					return invalid(id, "test %q: at %q", t.Name, e.At)
				}
			}
			for k := range e.Subjects {
				if !reflexdomain.SubjectType(k).Valid() {
					return invalid(id, "test %q: subject type %q", t.Name, k)
				}
			}
			for k := range e.Attrs {
				if !attrKeyRe.MatchString(k) {
					return invalid(id, "test %q: attribute %q", t.Name, k)
				}
			}
		}
	}
	return nil
}

// HasFiringAndQuiet reports whether the rule has at least one firing and
// one non-firing test (D11, D13).
func (r *Rule) HasFiringAndQuiet() bool {
	return slices.ContainsFunc(r.Tests, func(t Test) bool { return t.Fires }) &&
		slices.ContainsFunc(r.Tests, func(t Test) bool { return !t.Fires })
}

func checkKinds(id string, on []string) error {
	for _, k := range on {
		if !kindRe.MatchString(k) || len(k) > 128 {
			return invalid(id, "event kind %q", k)
		}
		if reflexdomain.ReflexKind(k) || k == "reflex.*" {
			return invalid(id, "rules never read Reflex's own events (%q)", k)
		}
	}
	return nil
}

func checkFields(id, what string, fs []string, min int) error {
	if len(fs) < min || len(fs) > MaxGroupBy {
		return invalid(id, "%s lists %d..%d fields", what, min, MaxGroupBy)
	}
	for _, f := range fs {
		if !fieldRe.MatchString(f) {
			return invalid(id, "%s field %q", what, f)
		}
		if m := subjectFld.FindStringSubmatch(f); m != nil && !reflexdomain.SubjectType(m[1]).Valid() {
			return invalid(id, "%s subject type %q", what, m[1])
		}
	}
	return nil
}

func duration(id, what, s string, limit time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 || d > limit {
		return 0, invalid(id, "%s must be a duration in (0, %s]", what, limit)
	}
	return d, nil
}

func (w *Window) validate(id string) error {
	if _, err := duration(id, "window.duration", w.Duration, MaxWindow); err != nil {
		return err
	}
	if w.Count < 1 || w.Count > MaxWindowCount {
		return invalid(id, "window.count 1..%d", MaxWindowCount)
	}
	if w.Distinct != "" && !fieldRe.MatchString(w.Distinct) {
		return invalid(id, "window.distinct field %q", w.Distinct)
	}
	return checkFields(id, "window.group_by", w.GroupBy, 0)
}

func (f *FirstSeen) validate(id string) error {
	if _, err := duration(id, "first_seen.horizon", f.Horizon, MaxHorizon); err != nil {
		return err
	}
	return checkFields(id, "first_seen.keys", f.Keys, 1)
}

func (s *Sequence) validate(id string) error {
	if len(s.Steps) < MinSequence || len(s.Steps) > MaxSequence {
		return invalid(id, "a sequence has %d..%d steps", MinSequence, MaxSequence)
	}
	if _, err := duration(id, "sequence.within", s.Within, MaxWithin); err != nil {
		return err
	}
	for _, st := range s.Steps {
		if len(st.On) == 0 || len(st.On) > MaxOn {
			return invalid(id, "each step lists 1..%d event kinds", MaxOn)
		}
		if err := checkKinds(id, st.On); err != nil {
			return err
		}
	}
	return checkFields(id, "sequence.group_by", s.GroupBy, 1)
}

// KindMatches reports whether kind is named by one of on (exact, or a
// "prefix.*" pattern).
func KindMatches(on []string, kind string) bool {
	for _, k := range on {
		if k == kind || (strings.HasSuffix(k, ".*") && strings.HasPrefix(kind, strings.TrimSuffix(k, "*"))) {
			return true
		}
	}
	return false
}
