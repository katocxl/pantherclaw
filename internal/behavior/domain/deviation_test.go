// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

var (
	agent = ids.NewV7()
	conn  = ids.NewV7()
	start = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
)

// usual is two runs a day for 20 days, 09:00 to 10:00: read then write on one
// connection, and a ten dollar refund a day.
func usual(t *testing.T) []bdomain.Action {
	t.Helper()
	ten := money.MustParse("10.00")
	var out []bdomain.Action
	for d := range 20 {
		for r := range 2 {
			run := ids.NewV7()
			at := start.AddDate(0, 0, d).Add(9*time.Hour + time.Duration(r)*10*time.Minute)
			out = append(out,
				bdomain.Action{ID: ids.NewV7(), Agent: agent, Run: run, Operation: "repo.read", Connection: conn, DestClass: "internal", At: at},
				bdomain.Action{ID: ids.NewV7(), Agent: agent, Run: run, Operation: "repo.write", Connection: conn, DestClass: "internal", At: at.Add(time.Minute)},
			)
		}
		out = append(out, bdomain.Action{
			ID: ids.NewV7(), Agent: agent, Run: ids.NewV7(), Operation: "payments.refund", Connection: conn, DestClass: "internal",
			At: start.AddDate(0, 0, d).Add(10 * time.Hour), Spent: &ten, Currency: "USD",
		})
	}
	return out
}

func profile(t *testing.T) bdomain.BehaviorProfile {
	t.Helper()
	return bdomain.Build(agent, bdomain.OriginReal, usual(t), start, start.AddDate(0, 0, 20), false)
}

func kinds(ds []bdomain.Deviation) []bdomain.Kind {
	out := make([]bdomain.Kind, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Kind)
	}
	return out
}

// TestBuild_HoldsToolsDestinationsHoursVolumesSequencesAndSpend: each thing a
// profile says, on known history. Covers: F930
func TestBuild_HoldsToolsDestinationsHoursVolumesSequencesAndSpend(t *testing.T) {
	p := profile(t)
	if p.State != bdomain.StateCollected || p.Actions != 100 || p.ActiveDays != 20 || p.Truncated {
		t.Fatalf("profile = %+v", p)
	}
	b := p.Body
	if len(b.Tools) != 3 || b.Tools[0].Operation != "repo.read" || b.Tools[0].Count != 40 {
		t.Errorf("tools = %+v", b.Tools)
	}
	if len(b.Destinations) != 1 || b.Destinations[0].Connection != conn.String() || b.Destinations[0].Class != "internal" {
		t.Errorf("destinations = %+v", b.Destinations)
	}
	if b.Hours[9] != 80 || b.Hours[10] != 20 || b.Hours[3] != 0 {
		t.Errorf("hours = %v", b.Hours)
	}
	if b.Volumes.MedianDaily != 5 || b.Volumes.MaxDaily != 5 || b.Volumes.MaxHourly != 4 {
		t.Errorf("volumes = %+v", b.Volumes)
	}
	if len(b.Sequences) != 1 || b.Sequences[0] != (bdomain.Sequence{From: "repo.read", To: "repo.write", Count: 40}) {
		t.Errorf("sequences = %+v", b.Sequences)
	}
	if len(b.Spend) != 1 || b.Spend[0].Currency != "USD" || b.Spend[0].MaxDaily != "10" || b.Spend[0].Days != 20 {
		t.Errorf("spend = %+v", b.Spend)
	}
}

// TestHR643_TooLittleHistoryInfersNothing: below the least history a profile
// says so, and nothing stands out, however odd the action. Covers: F930
func TestHR643_TooLittleHistoryInfersNothing(t *testing.T) {
	few := usual(t)[:10]
	p := bdomain.Build(agent, bdomain.OriginReal, few, start, start.AddDate(0, 0, 20), false)
	if p.State != bdomain.StateInsufficient {
		t.Fatalf("state = %s", p.State)
	}
	odd := bdomain.Action{Agent: agent, Run: ids.NewV7(), Operation: "secrets.dump", Connection: ids.NewV7(), At: start.AddDate(0, 1, 0).Add(3 * time.Hour)}
	if ds := bdomain.Compare(p, []bdomain.Action{odd}); len(ds) != 0 {
		t.Errorf("inferred from too little: %+v", ds)
	}
	if ds := bdomain.Context(p, odd); len(ds) != 0 {
		t.Errorf("context from too little: %+v", ds)
	}
	busy := bdomain.Build(agent, bdomain.OriginReal, slices.Repeat(few[:1], 60), start, start.AddDate(0, 0, 20), false)
	if busy.State != bdomain.StateInsufficient {
		t.Errorf("60 actions on one day: %s", busy.State)
	}
}

// TestCompare_NamesEachKindOnce: each deviation, once, with plain words;
// the usual run shows nothing. Covers: F932
func TestCompare_NamesEachKindOnce(t *testing.T) {
	p := profile(t)
	after := start.AddDate(0, 0, 21).Add(9 * time.Hour)
	run := ids.NewV7()
	normal := []bdomain.Action{
		{Agent: agent, Run: run, Operation: "repo.read", Connection: conn, At: after},
		{Agent: agent, Run: run, Operation: "repo.write", Connection: conn, At: after.Add(time.Minute)},
	}
	if ds := bdomain.Compare(p, normal); len(ds) != 0 {
		t.Fatalf("the usual run stood out: %+v", ds)
	}

	night := after.Add(18 * time.Hour)
	other := ids.NewV7()
	odd := []bdomain.Action{
		{Agent: agent, Run: run, Operation: "repo.read", Connection: conn, At: after},
		{Agent: agent, Run: run, Operation: "secrets.dump", Connection: other, DestClass: "public", At: after.Add(time.Minute)},
		{Agent: agent, Run: run, Operation: "secrets.dump", Connection: other, DestClass: "public", At: after.Add(2 * time.Minute)},
		{Agent: agent, Run: ids.NewV7(), Operation: "repo.read", Connection: conn, At: night},
	}
	ds := bdomain.Compare(p, odd)
	got := kinds(ds)
	slices.Sort(got)
	want := []bdomain.Kind{bdomain.KindNewDestination, bdomain.KindNewSequence, bdomain.KindNewSequence, bdomain.KindNewTool, bdomain.KindUnusualHour}
	if !slices.Equal(got, want) {
		t.Fatalf("kinds = %v, want %v: %+v", got, want, ds)
	}
	for _, d := range ds {
		if d.Text == "" || strings.ContainsAny(d.Text, "<>") {
			t.Errorf("text %q", d.Text)
		}
	}
}

// TestCompare_SpikesNeedAFloorAndAFactor: three times the busiest hour is not
// yet a spike, and neither is a small hour. The same for a day's spend, in
// money, never floats. Covers: F932
func TestCompare_SpikesNeedAFloorAndAFactor(t *testing.T) {
	p := profile(t)
	at := start.AddDate(0, 0, 21).Add(9 * time.Hour)
	burst := func(n int) []bdomain.Action {
		out := make([]bdomain.Action, n)
		for i := range out {
			out[i] = bdomain.Action{Agent: agent, Run: ids.NewV7(), Operation: "repo.read", Connection: conn, At: at.Add(time.Duration(i) * time.Second)}
		}
		return out
	}
	if got := kinds(bdomain.Compare(p, burst(bdomain.MinSpikeActions-1))); slices.Contains(got, bdomain.KindVolumeSpike) {
		t.Errorf("below the floor: %v", got)
	}
	if got := kinds(bdomain.Compare(p, burst(bdomain.MinSpikeActions))); !slices.Contains(got, bdomain.KindVolumeSpike) {
		t.Errorf("at the floor: %v", got)
	}
	spend := func(s string) []bdomain.Action {
		d := money.MustParse(s)
		return []bdomain.Action{{Agent: agent, Run: ids.NewV7(), Operation: "payments.refund", Connection: conn, At: at, Spent: &d, Currency: "USD"}}
	}
	if got := kinds(bdomain.Compare(p, spend("30.00"))); slices.Contains(got, bdomain.KindSpendSpike) {
		t.Errorf("exactly three times: %v", got)
	}
	if got := kinds(bdomain.Compare(p, spend("30.01"))); !slices.Contains(got, bdomain.KindSpendSpike) {
		t.Errorf("over three times: %v", got)
	}
}

// TestCompare_ACutListSaysNothing: a value missing from a list that was cut
// might have been cut away, so it isn't new. Covers: F930
func TestCompare_ACutListSaysNothing(t *testing.T) {
	var many []bdomain.Action
	for d := range 10 {
		for i := range bdomain.MaxTools {
			many = append(many, bdomain.Action{
				Agent: agent, Run: ids.NewV7(), Operation: "op." + time.Duration(i).String(), At: start.AddDate(0, 0, d).Add(9 * time.Hour),
			})
		}
		many = append(many, bdomain.Action{
			Agent: agent, Run: ids.NewV7(), Operation: "op.one-more", At: start.AddDate(0, 0, d).Add(9 * time.Hour),
		})
	}
	many = append(many, bdomain.Action{Agent: agent, Run: ids.NewV7(), Operation: "op.rare", At: start.Add(9 * time.Hour)})
	p := bdomain.Build(agent, bdomain.OriginReal, many, start, start.AddDate(0, 0, 20), false)
	if !p.Body.CutTools || !p.Truncated {
		t.Fatalf("cut = %v truncated = %v", p.Body.CutTools, p.Truncated)
	}
	ds := bdomain.Compare(p, []bdomain.Action{{Agent: agent, Run: ids.NewV7(), Operation: "op.rare", At: start.AddDate(0, 0, 21).Add(9 * time.Hour)}})
	if slices.Contains(kinds(ds), bdomain.KindNewTool) {
		t.Errorf("a cut list said new: %+v", ds)
	}
}

// TestContext_IsWhatOneActionShows: the approval page's lines. Covers: F934
func TestContext_IsWhatOneActionShows(t *testing.T) {
	p := profile(t)
	at := start.AddDate(0, 0, 21).Add(9 * time.Hour)
	ds := bdomain.Context(p, bdomain.Action{Agent: agent, Run: ids.NewV7(), Operation: "repo.delete", Connection: conn, At: at})
	if len(ds) != 1 || ds[0].Kind != bdomain.KindNewTool || ds[0].Text != "Never done repo.delete in the last 30 days" {
		t.Fatalf("context = %+v", ds)
	}
	if ds := bdomain.Context(p, bdomain.Action{Agent: agent, Run: ids.NewV7(), Operation: "repo.read", Connection: conn, At: at}); len(ds) != 0 {
		t.Fatalf("a usual action stood out: %+v", ds)
	}
}
