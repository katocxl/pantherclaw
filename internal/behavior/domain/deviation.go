// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Kind is one way an action stands out.
type Kind string

// Deviation kinds.
const (
	KindNewTool        Kind = "NEW_TOOL"
	KindNewDestination Kind = "NEW_DESTINATION"
	KindUnusualHour    Kind = "UNUSUAL_HOUR"
	KindNewSequence    Kind = "NEW_SEQUENCE"
	KindVolumeSpike    Kind = "VOLUME_SPIKE"
	KindSpendSpike     Kind = "SPEND_SPIKE"
)

// Deviation is one thing that stands out, with the action that showed it.
type Deviation struct {
	Kind Kind
	// Value names what stood out; with Kind it keys the alert.
	Value  string
	Action Action
	// Text is plain words from recorded names, never markup.
	Text string
}

// Comparison is what a batch of newer actions showed against a profile.
type Comparison struct {
	Deviations []Deviation
}

// Compare sets actions newer than p against p (HR-643): nothing is inferred
// from a profile without enough history, and a "new" comparison is off for a
// list that was cut, where a missing value says nothing. Each deviation
// appears once, on its earliest action.
func Compare(p BehaviorProfile, actions []Action) []Deviation {
	if p.State != StateCollected {
		return nil
	}
	sorted := slices.Clone(actions)
	slices.SortStableFunc(sorted, func(a, b Action) int { return a.At.Compare(b.At) })

	tools, dests, seqs := knownTools(p), knownDestinations(p), knownSequences(p)
	seen := map[[2]string]bool{}
	var out []Deviation
	add := func(d Deviation) {
		k := [2]string{string(d.Kind), d.Value}
		if !seen[k] {
			seen[k] = true
			out = append(out, d)
		}
	}

	last := map[ids.UUID]string{}
	hourly, daySpend := map[string]int64{}, map[string]money.Decimal{}
	spikeAt, spendAt := map[string]Action{}, map[string]Action{}
	for _, a := range sorted {
		add2 := single(p, a, tools, dests)
		for _, d := range add2 {
			add(d)
		}
		if prev, ok := last[a.Run]; ok && !p.Body.CutSequences && !seqs[[2]string{prev, a.Operation}] {
			add(Deviation{
				Kind: KindNewSequence, Value: prev + " -> " + a.Operation, Action: a,
				Text: fmt.Sprintf("Never ran %s right after %s in the last %d days", a.Operation, prev, windowDays()),
			})
		}
		last[a.Run] = a.Operation
		h := a.At.UTC().Format("2006-01-02T15")
		hourly[h]++
		if _, ok := spikeAt[h]; !ok {
			spikeAt[h] = a
		}
		if a.Spent != nil && a.Currency != "" {
			k := spendKey(a.At.UTC().Format(time.DateOnly), a.Currency)
			if sum, err := daySpend[k].Add(*a.Spent); err == nil {
				daySpend[k] = sum
				spendAt[k] = a
			}
		}
	}
	for _, h := range sortedKeys(hourly) {
		if n := hourly[h]; n >= MinSpikeActions && n > SpikeFactor*p.Body.Volumes.MaxHourly {
			add(Deviation{
				Kind: KindVolumeSpike, Value: h, Action: spikeAt[h],
				Text: fmt.Sprintf("%d actions in an hour; the busiest hour in the last %d days had %d", n, windowDays(), p.Body.Volumes.MaxHourly),
			})
		}
	}
	for _, k := range sortedKeys(daySpend) {
		a := spendAt[k]
		if over, seenMax := overSpend(p, a.Currency, daySpend[k]); over {
			add(Deviation{
				Kind: KindSpendSpike, Value: k, Action: a,
				Text: fmt.Sprintf("%s %s asked for in a day; the highest day in the last %d days was %s", daySpend[k], a.Currency, windowDays(), seenMax),
			})
		}
	}
	return out
}

// Context is what stands out about one held action, for the approval page.
func Context(p BehaviorProfile, a Action) []Deviation {
	if p.State != StateCollected {
		return nil
	}
	return single(p, a, knownTools(p), knownDestinations(p))
}

// single is what one action shows by itself.
func single(p BehaviorProfile, a Action, tools, dests map[string]bool) []Deviation {
	var out []Deviation
	if !p.Body.CutTools && !tools[a.Operation] {
		out = append(out, Deviation{
			Kind: KindNewTool, Value: a.Operation, Action: a,
			Text: fmt.Sprintf("Never done %s in the last %d days", a.Operation, windowDays()),
		})
	}
	if k := connectionKey(a.Connection); k != "" && !p.Body.CutDestinations && !dests[k] {
		out = append(out, Deviation{
			Kind: KindNewDestination, Value: k, Action: a,
			Text: fmt.Sprintf("Never used this connection (%s) in the last %d days", destWord(a.DestClass), windowDays()),
		})
	}
	if h := a.At.UTC().Hour(); len(p.Body.Hours) == 24 && p.Body.Hours[h] == 0 {
		out = append(out, Deviation{
			Kind: KindUnusualHour, Value: fmt.Sprintf("%02d", h), Action: a,
			Text: fmt.Sprintf("Never acted at %02d:00 UTC in the last %d days", h, windowDays()),
		})
	}
	return out
}

func destWord(class string) string {
	if class == "" {
		return "no class recorded"
	}
	return "class " + class
}

// overSpend reports a day above SpikeFactor times the highest seen. A
// currency never seen before is not compared: it is the destination or the
// tool that is new.
func overSpend(p BehaviorProfile, currency string, day money.Decimal) (bool, string) {
	for _, s := range p.Body.Spend {
		if s.Currency != currency {
			continue
		}
		highest, err := money.Parse(s.MaxDaily)
		if err != nil {
			return false, ""
		}
		limit, err := highest.MulInt(SpikeFactor)
		if err != nil {
			return false, ""
		}
		return day.Cmp(limit) > 0, s.MaxDaily
	}
	return false, ""
}

func windowDays() int { return int(Window / (24 * time.Hour)) }

func knownTools(p BehaviorProfile) map[string]bool {
	out := make(map[string]bool, len(p.Body.Tools))
	for _, t := range p.Body.Tools {
		out[t.Operation] = true
	}
	return out
}

func knownDestinations(p BehaviorProfile) map[string]bool {
	out := make(map[string]bool, len(p.Body.Destinations))
	for _, d := range p.Body.Destinations {
		out[d.Connection] = true
	}
	return out
}

func knownSequences(p BehaviorProfile) map[[2]string]bool {
	out := make(map[[2]string]bool, len(p.Body.Sequences))
	for _, s := range p.Body.Sequences {
		out[[2]string{s.From, s.To}] = true
	}
	return out
}
