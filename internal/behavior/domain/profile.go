// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain is behaviour analytics' pure core (G0 M27 D502, D506; F930;
// HR-641 to HR-644): a BehaviorProfile of what an agent usually does, built
// from its own transactions, and the deviations of newer actions from it.
//
// Everything this package says is inference on thresholds nobody has checked
// against real incidents: each result is labelled so (F648, F801), and no
// decision reads any of it. A profile with too little history infers
// nothing. A count is a sample, never a measure of value (HR-539).
//
// Import it as bdomain. A cohort's Baseline (internal/cohorts) is a different
// thing: that compares a fleet's configuration.
package domain

import (
	"cmp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Origin says which activity a profile rests on (HR-642).
type Origin string

// Origins.
const (
	OriginReal      Origin = "REAL"
	OriginSimulated Origin = "SIMULATED"
)

// State says what a profile can rest on.
type State string

// States. A missing profile is NOT_COLLECTED, never zero (HR-643).
const (
	StateCollected    State = "COLLECTED"
	StateInsufficient State = "INSUFFICIENT_HISTORY"
	StateNotCollected State = "NOT_COLLECTED"
)

// Method is the version of what a profile holds and how it is compared.
const Method = "n13.1"

// Labels every result carries (F648, F801). DefinitionStatus is the same
// word as outcomes.DefinitionUnvalidated, which outcome metrics read.
const (
	Basis            = "INFERRED"
	DefinitionStatus = "UNVALIDATED"
	Label            = "Inferred from this agent's own recorded actions. The thresholds are unvalidated. This is not evidence of misuse, " +
		"and a quiet result is not a clean one: the agent shapes its own baseline, and activity outside PantherClaw and the " +
		"arguments of its actions are not seen."
)

// The method's bounds and thresholds. They are unvalidated (F801): none was
// checked against a real incident, and each result says so.
const (
	// Window is the history a profile covers.
	Window = 30 * 24 * time.Hour
	// MinActions and MinDays are the least history anything is inferred from.
	MinActions = 50
	MinDays    = 7
	// A spike is more than SpikeFactor times the highest seen, and at least
	// MinSpikeActions actions in an hour.
	SpikeFactor     = 3
	MinSpikeActions = 20
	// The most entries a profile keeps of each list.
	MaxTools        = 200
	MaxDestinations = 200
	MaxSequences    = 500
	MaxCurrencies   = 16
)

// Action is one recorded action of an agent. It carries names, ids and
// amounts only: never arguments or payloads (HR-056).
type Action struct {
	ID        ids.UUID
	Agent     ids.UUID
	Run       ids.UUID
	Operation string
	// Connection is zero for an action that named none.
	Connection ids.UUID
	DestClass  string
	At         time.Time
	// Spent is the amount of an allowed action, nil for any other.
	Spent    *money.Decimal
	Currency string
	// Generated marks made-up history: no transaction backs it (HR-642).
	Generated bool
	// Known marks an action that was allowed and ran (decision ALLOW or
	// ALLOW_WITH_OBLIGATIONS, transaction FINAL), or generated history. Only
	// a known action makes a tool, connection, hour or sequence known: a
	// hold, a denial or a retry of either never does (D526).
	Known bool
}

// Tool is one operation and how often the agent ran it.
type Tool struct {
	Operation string `json:"operation"`
	Count     int64  `json:"count"`
}

// Destination is one connection and how often it was used.
type Destination struct {
	Connection string `json:"connection,omitzero"`
	Class      string `json:"class,omitzero"`
	Count      int64  `json:"count"`
}

// Volumes are actions per active day, and the busiest hour.
type Volumes struct {
	MedianDaily int64 `json:"median_daily"`
	P90Daily    int64 `json:"p90_daily"`
	MaxDaily    int64 `json:"max_daily"`
	MaxHourly   int64 `json:"max_hourly"`
}

// Sequence is one operation following another in a run.
type Sequence struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int64  `json:"count"`
}

// Spend is one currency's spending per day it was spent.
type Spend struct {
	Currency    string `json:"currency"`
	MedianDaily string `json:"median_daily"`
	MaxDaily    string `json:"max_daily"`
	Days        int    `json:"days"`
}

// Body is the stored part of a profile.
type Body struct {
	Tools        []Tool        `json:"tools"`
	Destinations []Destination `json:"destinations"`
	Hours        []int64       `json:"hours"`
	Volumes      Volumes       `json:"volumes"`
	Sequences    []Sequence    `json:"sequences"`
	Spend        []Spend       `json:"spend"`
	// The lists that were cut: a value missing from a cut list says nothing.
	CutTools, CutDestinations, CutSequences bool `json:",omitzero"`
	// NotAllowed counts the actions in the window that were not allowed and
	// run: held, denied, refused or still open. They are counted apart and
	// none of them is in the lists above (D526).
	NotAllowed int64 `json:"not_allowed"`
}

// BehaviorProfile is what an agent usually does.
type BehaviorProfile struct {
	Agent      ids.UUID
	Origin     Origin
	State      State
	Start, End time.Time
	Actions    int64
	ActiveDays int
	// Truncated: the org's history outran the method's cap, or a list was
	// cut.
	Truncated bool
	Body      Body
	AsOf      time.Time
}

func spendKey(day, currency string) string { return day + "|" + currency }

// Build is the profile of one agent's actions in [start, end). It reads the
// actions in time order, so sequences follow each run. Only known actions
// shape it; the others are counted in Body.NotAllowed and nothing more.
func Build(agent ids.UUID, origin Origin, actions []Action, start, end time.Time, truncated bool) BehaviorProfile {
	sorted := make([]Action, 0, len(actions))
	var notAllowed int64
	for _, a := range actions {
		if a.Known {
			sorted = append(sorted, a)
		} else {
			notAllowed++
		}
	}
	slices.SortStableFunc(sorted, func(a, b Action) int { return a.At.Compare(b.At) })

	tools := map[string]int64{}
	dests := map[[2]string]int64{}
	seqs := map[[2]string]int64{}
	days, hourly := map[string]int64{}, map[string]int64{}
	spentDay := map[string]money.Decimal{}
	spentCurrencies := map[string]bool{}
	last := map[ids.UUID]string{}
	hours := make([]int64, 24)

	for _, a := range sorted {
		tools[a.Operation]++
		dests[[2]string{connectionKey(a.Connection), a.DestClass}]++
		at := a.At.UTC()
		hours[at.Hour()]++
		day := at.Format(time.DateOnly)
		days[day]++
		hourly[at.Format("2006-01-02T15")]++
		if prev, ok := last[a.Run]; ok {
			seqs[[2]string{prev, a.Operation}]++
		}
		last[a.Run] = a.Operation
		if a.Spent != nil && a.Currency != "" && !a.Spent.IsZero() {
			k := spendKey(day, a.Currency)
			if sum, err := spentDay[k].Add(*a.Spent); err == nil {
				spentDay[k] = sum
				spentCurrencies[a.Currency] = true
			}
		}
	}

	body := Body{Hours: hours, Volumes: volumes(days, hourly), Spend: spends(spentDay, spentCurrencies), NotAllowed: notAllowed}
	body.Tools, body.CutTools = topTools(tools)
	body.Destinations, body.CutDestinations = topDestinations(dests)
	body.Sequences, body.CutSequences = topSequences(seqs)

	p := BehaviorProfile{
		Agent: agent, Origin: origin, Start: start, End: end, Actions: int64(len(sorted)), ActiveDays: len(days),
		Truncated: truncated || body.CutTools || body.CutDestinations || body.CutSequences, Body: body, State: StateInsufficient,
	}
	if p.Actions >= MinActions && p.ActiveDays >= MinDays {
		p.State = StateCollected
	}
	return p
}

func connectionKey(c ids.UUID) string {
	if c.IsZero() {
		return ""
	}
	return c.String()
}

func volumes(days, hourly map[string]int64) Volumes {
	daily := make([]int64, 0, len(days))
	for _, n := range days {
		daily = append(daily, n)
	}
	slices.Sort(daily)
	var v Volumes
	if len(daily) > 0 {
		v.MedianDaily = daily[len(daily)/2]
		v.P90Daily = daily[len(daily)*9/10]
		v.MaxDaily = daily[len(daily)-1]
	}
	for _, n := range hourly {
		v.MaxHourly = max(v.MaxHourly, n)
	}
	return v
}

func spends(spentDay map[string]money.Decimal, currencies map[string]bool) []Spend {
	out := make([]Spend, 0, len(currencies))
	for _, c := range sortedKeys(currencies) {
		var perDay []money.Decimal
		for k, v := range spentDay {
			if len(k) > 11 && k[11:] == c {
				perDay = append(perDay, v)
			}
		}
		slices.SortFunc(perDay, money.Decimal.Cmp)
		out = append(out, Spend{
			Currency: c, MedianDaily: perDay[len(perDay)/2].String(), MaxDaily: perDay[len(perDay)-1].String(), Days: len(perDay),
		})
	}
	if len(out) > MaxCurrencies {
		out = out[:MaxCurrencies]
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func topTools(m map[string]int64) ([]Tool, bool) {
	out := make([]Tool, 0, len(m))
	for op, n := range m {
		out = append(out, Tool{Operation: op, Count: n})
	}
	slices.SortFunc(out, func(a, b Tool) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Operation, b.Operation))
	})
	return cut(out, MaxTools)
}

func topDestinations(m map[[2]string]int64) ([]Destination, bool) {
	out := make([]Destination, 0, len(m))
	for k, n := range m {
		out = append(out, Destination{Connection: k[0], Class: k[1], Count: n})
	}
	slices.SortFunc(out, func(a, b Destination) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Connection, b.Connection), cmp.Compare(a.Class, b.Class))
	})
	return cut(out, MaxDestinations)
}

func topSequences(m map[[2]string]int64) ([]Sequence, bool) {
	out := make([]Sequence, 0, len(m))
	for k, n := range m {
		out = append(out, Sequence{From: k[0], To: k[1], Count: n})
	}
	slices.SortFunc(out, func(a, b Sequence) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To))
	})
	return cut(out, MaxSequences)
}

func cut[T any](s []T, n int) ([]T, bool) {
	if len(s) > n {
		return s[:n], true
	}
	return s, false
}
