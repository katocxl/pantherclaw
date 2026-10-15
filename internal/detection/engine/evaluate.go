// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// Cardinality caps (D10, HR-240).
const (
	// MaxGroups is the most group keys one rule keeps per window.
	MaxGroups = 10_000
	// MaxSeen is the most first-seen keys one rule keeps.
	MaxSeen = 100_000
	// OverflowKey is the group events count into once a rule is at its cap.
	OverflowKey = "__overflow__"
	// MaxConsecutiveErrors disables a rule after this many evaluation
	// errors in a row.
	MaxConsecutiveErrors = 10
)

// Progress is how far one group has come through a sequence.
type Progress struct {
	Step     int
	Started  time.Time
	Updated  time.Time
	Evidence []ids.UUID
}

// State is the engine's working memory for one org.
type State interface {
	// Window counts one event of group at t and returns the count (the
	// number of distinct values when distinct is set) of the group's events
	// within dur up to t. Once the rule holds MaxGroups groups a new group
	// counts into OverflowKey and overflow is true.
	Window(ctx context.Context, rule, group string, at time.Time, dur time.Duration, distinct string, counted bool) (int, bool, error)
	// Seen records key at t and reports whether it was new within horizon.
	// Once the rule holds MaxSeen keys a new key is not stored, isNew is
	// false and overflow is true.
	Seen(ctx context.Context, rule string, key [32]byte, at time.Time, horizon time.Duration) (isNew, overflow bool, err error)
	// Sequence returns a group's progress, if any.
	Sequence(ctx context.Context, rule, group string) (Progress, bool, error)
	// SetSequence stores a group's progress; ClearSequence removes it.
	SetSequence(ctx context.Context, rule, group string, p Progress) error
	ClearSequence(ctx context.Context, rule, group string) error
}

// Firing is a rule match that raises a signal.
type Firing struct {
	// Group is the detector's group (window, first-seen key or sequence
	// group); empty for a plain match.
	Group    string
	Count    int
	Evidence []ids.UUID
}

// Result of evaluating one rule on one event.
type Result struct {
	Fired    *Firing
	Overflow bool
}

// Evaluate runs c on e. Kinds the rule does not read, and Reflex's own
// entries, are skipped without evaluation.
func Evaluate(ctx context.Context, st State, c *Compiled, e feed.Event) (Result, error) {
	if reflexdomain.ReflexKind(e.Kind) {
		return Result{}, nil
	}
	r := c.Rule
	if r.Sequence != nil {
		return sequence(ctx, st, c, e)
	}
	if !rules.KindMatches(r.On, e.Kind) {
		return Result{}, nil
	}
	var vars map[string]any
	if c.match != nil {
		vars = record(e)
	}
	ok, err := eval(ctx, c.match, vars)
	if err != nil || !ok {
		return Result{}, err
	}
	switch {
	case r.Window != nil:
		w := r.Window
		group, ok := key(e, w.GroupBy)
		if !ok {
			return Result{}, nil
		}
		distinct := ""
		if w.Distinct != "" {
			if distinct = field(e, w.Distinct); distinct == "" {
				return Result{}, nil
			}
		}
		n, overflow, err := st.Window(ctx, r.ID, group, e.OccurredAt, c.window, distinct, w.Distinct != "")
		if err != nil {
			return Result{}, err
		}
		if overflow {
			group = OverflowKey
		}
		res := Result{Overflow: overflow}
		if n >= w.Count {
			res.Fired = &Firing{Group: group, Count: n, Evidence: []ids.UUID{e.ID}}
		}
		return res, nil
	case r.FirstSeen != nil:
		k, ok := key(e, r.FirstSeen.Keys)
		if !ok {
			return Result{}, nil
		}
		sum := sha256.Sum256([]byte(k))
		isNew, overflow, err := st.Seen(ctx, r.ID, sum, e.OccurredAt, c.horizon)
		if err != nil {
			return Result{}, err
		}
		res := Result{Overflow: overflow}
		if isNew {
			res.Fired = &Firing{Group: hex.EncodeToString(sum[:8]), Count: 1, Evidence: []ids.UUID{e.ID}}
		}
		return res, nil
	}
	return Result{Fired: &Firing{Count: 1, Evidence: []ids.UUID{e.ID}}}, nil
}

// sequence advances a group's progress: an event matching the next step
// within the window advances it; one matching the first step (re)starts it.
func sequence(ctx context.Context, st State, c *Compiled, e feed.Event) (Result, error) {
	s := c.Rule.Sequence
	group, ok := key(e, s.GroupBy)
	if !ok {
		return Result{}, nil
	}
	var vars map[string]any
	matches := func(i int) (bool, error) {
		if !rules.KindMatches(s.Steps[i].On, e.Kind) {
			return false, nil
		}
		if vars == nil {
			vars = record(e)
		}
		return eval(ctx, c.steps[i], vars)
	}
	p, have, err := st.Sequence(ctx, c.Rule.ID, group)
	if err != nil {
		return Result{}, err
	}
	if have && e.OccurredAt.Sub(p.Started) > c.within {
		have = false
		if err := st.ClearSequence(ctx, c.Rule.ID, group); err != nil {
			return Result{}, err
		}
	}
	if have && p.Step < len(s.Steps) {
		ok, err := matches(p.Step)
		if err != nil {
			return Result{}, err
		}
		if ok {
			p.Step++
			p.Updated = e.OccurredAt
			p.Evidence = append(p.Evidence, e.ID)
			if p.Step == len(s.Steps) {
				if err := st.ClearSequence(ctx, c.Rule.ID, group); err != nil {
					return Result{}, err
				}
				return Result{Fired: &Firing{Group: group, Count: p.Step, Evidence: p.Evidence}}, nil
			}
			return Result{}, st.SetSequence(ctx, c.Rule.ID, group, p)
		}
	}
	if !have {
		ok, err := matches(0)
		if err != nil || !ok {
			return Result{}, err
		}
		return Result{}, st.SetSequence(ctx, c.Rule.ID, group,
			Progress{Step: 1, Started: e.OccurredAt, Updated: e.OccurredAt, Evidence: []ids.UUID{e.ID}})
	}
	return Result{}, nil
}

// groupKeys map a rule's group (F603) to the subject it groups by.
var groupKeys = map[string][]reflexdomain.SubjectType{
	"run": {reflexdomain.SubjectRun}, "agent": {reflexdomain.SubjectAgent},
	"principal": {reflexdomain.SubjectUser, reflexdomain.SubjectServiceAccount},
	"grant":     {reflexdomain.SubjectGrant}, "connection": {reflexdomain.SubjectConnection},
	"target": {reflexdomain.SubjectResource, reflexdomain.SubjectConnection},
}

// GroupKey is the evidence-based grouping key of e under group ("" when e
// names no such subject).
func GroupKey(group string, e feed.Event) string {
	for _, t := range groupKeys[group] {
		if id, ok := e.Subject(t); ok {
			k := group + ":" + id
			if group == "target" && e.Operation != "" {
				k += "/" + e.Operation
			}
			return k
		}
	}
	return ""
}

// Signal builds the signal of a firing.
func Signal(c *Compiled, e feed.Event, f Firing) reflexdomain.Signal {
	r := c.Rule
	s := reflexdomain.Signal{
		Org: e.Org, Source: reflexdomain.SourceDetection, RuleID: r.ID, RuleVersion: r.Version, RuleDigest: c.Digest,
		PackVersion: c.PackVersion, Title: r.Title, Summary: truncate(r.Description, reflexdomain.MaxSummary),
		Severity: r.Severity, Attention: r.Attention, Basis: r.Basis, Subjects: e.Subjects,
		GroupKey: GroupKey(r.Group, e), ATLAS: r.ATLAS, OWASP: r.OWASP, OccurredAt: e.OccurredAt, Test: e.Test,
		Facts: map[string]string{"event_kind": truncate(e.Kind, 512), "count": strconv.Itoa(f.Count)},
	}
	if e.Operation != "" {
		s.Facts["operation"] = truncate(e.Operation, 512)
	}
	if e.Decision != "" {
		s.Facts["decision"] = e.Decision
	}
	if e.Reason != "" {
		s.Facts["reason"] = truncate(e.Reason, 512)
	}
	for _, id := range f.Evidence {
		s.Evidence = append(s.Evidence, reflexdomain.EvidenceRef{Kind: reflexdomain.EvidenceLedger, ID: id})
	}
	if t, ok := e.Subject(reflexdomain.SubjectTransaction); ok {
		if id, err := ids.ParseUUID(t); err == nil {
			s.Evidence = append(s.Evidence, reflexdomain.EvidenceRef{Kind: reflexdomain.EvidenceTransaction, ID: id})
		}
	}
	if f.Group != "" {
		sum := sha256.Sum256([]byte(f.Group))
		s.DedupeKey = "detection|" + r.ID + "|" + hex.EncodeToString(sum[:16])
	}
	if len(s.Subjects) > reflexdomain.MaxSubjects {
		s.Subjects = s.Subjects[:reflexdomain.MaxSubjects]
	}
	if len(s.Evidence) > reflexdomain.MaxEvidence {
		s.Evidence = s.Evidence[:reflexdomain.MaxEvidence]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
