// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

type windowEvent struct {
	at       time.Time
	distinct string
}

// Memory is an in-memory State for rule tests. It keeps the same caps as
// the database state; the caps are fields so tests can lower them.
type Memory struct {
	MaxGroups, MaxSeen int
	windows            map[string]map[string][]windowEvent
	seen               map[string]map[[32]byte]time.Time
	seqs               map[string]map[string]Progress
}

// NewMemory returns an empty in-memory state with the production caps.
func NewMemory() *Memory {
	return &Memory{
		MaxGroups: MaxGroups, MaxSeen: MaxSeen, windows: map[string]map[string][]windowEvent{},
		seen: map[string]map[[32]byte]time.Time{}, seqs: map[string]map[string]Progress{},
	}
}

// Window implements State.
func (m *Memory) Window(_ context.Context, rule, group string, at time.Time, dur time.Duration, distinct string, counted bool,
) (int, bool, error) {
	gs := m.windows[rule]
	if gs == nil {
		gs = map[string][]windowEvent{}
		m.windows[rule] = gs
	}
	from := at.Add(-dur)
	live := 0
	for g, evs := range gs {
		if slices.ContainsFunc(evs, func(w windowEvent) bool { return w.at.After(from) }) {
			live++
		} else {
			delete(gs, g)
		}
	}
	overflow := false
	if _, ok := gs[group]; !ok && live >= m.MaxGroups {
		group, overflow = OverflowKey, true
	}
	evs := append(slices.DeleteFunc(gs[group], func(w windowEvent) bool { return !w.at.After(from) }), windowEvent{at, distinct})
	gs[group] = evs
	if !counted {
		return len(evs), overflow, nil
	}
	vals := map[string]bool{}
	for _, w := range evs {
		vals[w.distinct] = true
	}
	return len(vals), overflow, nil
}

// Seen implements State.
func (m *Memory) Seen(_ context.Context, rule string, key [32]byte, at time.Time, horizon time.Duration) (bool, bool, error) {
	ks := m.seen[rule]
	if ks == nil {
		ks = map[[32]byte]time.Time{}
		m.seen[rule] = ks
	}
	last, ok := ks[key]
	if !ok && len(ks) >= m.MaxSeen {
		return false, true, nil
	}
	ks[key] = at
	return !ok || at.Sub(last) > horizon, false, nil
}

// Sequence implements State.
func (m *Memory) Sequence(_ context.Context, rule, group string) (Progress, bool, error) {
	p, ok := m.seqs[rule][group]
	return p, ok, nil
}

// SetSequence implements State.
func (m *Memory) SetSequence(_ context.Context, rule, group string, p Progress) error {
	if m.seqs[rule] == nil {
		m.seqs[rule] = map[string]Progress{}
	}
	m.seqs[rule][group] = p
	return nil
}

// ClearSequence implements State.
func (m *Memory) ClearSequence(_ context.Context, rule, group string) error {
	delete(m.seqs[rule], group)
	return nil
}

// TestResult is the outcome of one rule test.
type TestResult struct {
	Name   string `json:"name"`
	Fires  bool   `json:"fires"`
	Fired  bool   `json:"fired"`
	Passed bool   `json:"passed"`
	Error  string `json:"error,omitzero"`
}

// testStart is the fixed start time of rule tests.
var testStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// RunTests runs every test of c on a fresh in-memory state each and
// reports whether each fired as it says. Test events are marked test.
func RunTests(ctx context.Context, c *Compiled) []TestResult {
	out := make([]TestResult, 0, len(c.Rule.Tests))
	for _, t := range c.Rule.Tests {
		res := TestResult{Name: t.Name, Fires: t.Fires}
		st := NewMemory()
		for i, te := range t.Events {
			r, err := Evaluate(ctx, st, c, TestFeedEvent(int64(i+1), te))
			if err != nil {
				res.Error = err.Error()
				break
			}
			res.Fired = res.Fired || r.Fired != nil
		}
		res.Passed = res.Error == "" && res.Fired == t.Fires
		out = append(out, res)
	}
	return out
}

// AllPass reports whether every result passed and there is at least one
// firing and one non-firing test among them.
func AllPass(rs []TestResult) bool {
	fires, quiet := false, false
	for _, r := range rs {
		if !r.Passed {
			return false
		}
		fires, quiet = fires || r.Fires, quiet || !r.Fires
	}
	return fires && quiet
}

// TestFeedEvent turns a test fixture into a feed event.
func TestFeedEvent(seq int64, te rules.TestEvent) feed.Event {
	at := testStart
	if te.At != "" {
		d, _ := time.ParseDuration(te.At)
		at = at.Add(d)
	}
	e := feed.Event{
		Seq: seq, ID: ids.NewV7(), Kind: te.Kind, OccurredAt: at, ActorType: te.ActorType, ActorID: te.ActorID,
		Decision: te.Decision, Reason: te.Reason, Operation: te.Operation, Mode: te.Mode, Outcome: te.Outcome,
		Environment: te.Environment, DestinationClass: te.DestinationClass, Test: true, Attrs: te.Attrs,
	}
	for _, t := range reflexdomain.SubjectTypes() {
		if id, ok := te.Subjects[string(t)]; ok {
			e.Subjects = append(e.Subjects, reflexdomain.Subject{Type: t, ID: id})
		}
	}
	return e
}

// CheckTests compiles nothing; it runs c's tests and returns an error
// naming the first failure, or a missing firing or non-firing test.
func CheckTests(ctx context.Context, c *Compiled) error {
	rs := RunTests(ctx, c)
	for _, r := range rs {
		if !r.Passed {
			return fmt.Errorf("%w: %s: test %q: fires %v, fired %v %s", rules.ErrInvalid, c.Rule.ID, r.Name, r.Fires, r.Fired, r.Error)
		}
	}
	if !AllPass(rs) {
		return fmt.Errorf("%w: %s: needs at least one firing and one non-firing test", rules.ErrInvalid, c.Rule.ID)
	}
	return nil
}
