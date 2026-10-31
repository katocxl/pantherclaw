// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/posture/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
)

var now = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func keys(in []domain.RankedFinding) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		out = append(out, f.SourceID)
	}
	return out
}

// TestHR580_RankOrdersByTheTupleAndSaysWhich: severity beats production,
// production beats ownership, ownership beats age, the stable id settles the
// rest, and rank_reasons states which applied (D203).
// Covers: F862
func TestHR580_RankOrdersByTheTupleAndSaysWhich(t *testing.T) {
	old := now.Add(-72 * time.Hour)
	in := []domain.Finding{
		{SourceID: "young", Severity: domain.SeverityHigh, Since: now.Add(-time.Hour)},
		{SourceID: "low-prod", Severity: domain.SeverityLow, ReachesProduction: true, Unowned: true, Since: old},
		{SourceID: "old", Severity: domain.SeverityHigh, Since: old},
		{SourceID: "unowned", Severity: domain.SeverityHigh, Unowned: true, Since: now},
		{SourceID: "prod", Severity: domain.SeverityHigh, ReachesProduction: true, Since: now},
		{SourceID: "critical", Severity: domain.SeverityCritical, Since: now},
		{SourceID: "b-tie", Severity: domain.SeverityHigh, Since: old},
		{SourceID: "a-tie", Severity: domain.SeverityHigh, Since: old},
	}
	got := domain.Rank(in, now)
	want := []string{"critical", "prod", "unowned", "a-tie", "b-tie", "old", "young", "low-prod"}
	if !slices.Equal(keys(got), want) {
		t.Fatalf("order %v, want %v", keys(got), want)
	}
	last := got[len(got)-1]
	wantReasons := []string{"severity:LOW", "reaches_production", "unowned", "age_days:3"}
	if !slices.Equal(last.RankReasons, wantReasons) {
		t.Errorf("reasons %v, want %v", last.RankReasons, wantReasons)
	}
	if r := got[0].RankReasons; !slices.Equal(r, []string{"severity:CRITICAL"}) {
		t.Errorf("a key that did not apply is stated: %v", r)
	}
}

// TestHR580_NoScoreField: no field of the finding, ranked or not, is a
// score, a weight or a number for its risk (F797).
// Covers: F862
func TestHR580_NoScoreField(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[domain.Finding](), reflect.TypeFor[domain.RankedFinding](), reflect.TypeFor[domain.Fix](),
	} {
		for f := range typ.Fields() {
			n := strings.ToLower(f.Name)
			if strings.Contains(n, "score") || strings.Contains(n, "weight") || strings.Contains(n, "rating") {
				t.Errorf("%s.%s", typ.Name(), f.Name)
			}
			if k := f.Type.Kind(); k == reflect.Float32 || k == reflect.Float64 {
				t.Errorf("%s.%s is a number", typ.Name(), f.Name)
			}
		}
	}
}

// TestNormalizeStatesWhereSeverityCameFrom: a stated severity is kept in
// upper case; none, or text that is no severity, comes from the table.
// Covers: F861
func TestNormalizeStatesWhereSeverityCameFrom(t *testing.T) {
	f := domain.Finding{Kind: domain.KindNewTool, Severity: "high"}.Normalize()
	if f.Severity != domain.SeverityHigh || f.SeverityBasis != domain.BasisStated {
		t.Errorf("stated: %+v", f)
	}
	for _, s := range []domain.Severity{"", "urgent"} {
		f := domain.Finding{Kind: domain.KindNewResource, Severity: s}.Normalize()
		if f.Severity != domain.SeverityLow || f.SeverityBasis != domain.BasisByKind {
			t.Errorf("%q: %+v", s, f)
		}
	}
	if got := domain.KindSeverity("anything_else"); got != domain.SeverityMedium {
		t.Errorf("unknown kind: %s", got)
	}
}

// TestOWASPValuesAreKnown: D205, every value is on the rules' closed list,
// and every posture kind is mapped.
// Covers: F864
func TestOWASPValuesAreKnown(t *testing.T) {
	for _, k := range domain.OWASPKinds() {
		vals := domain.OWASP(k)
		if len(vals) == 0 {
			t.Errorf("%s has no risk", k)
		}
		for _, v := range vals {
			if !rules.KnownOWASP(v) {
				t.Errorf("%s maps to unknown %s", k, v)
			}
		}
	}
	for _, k := range pdomain.Kinds {
		if len(domain.OWASP(string(k))) == 0 {
			t.Errorf("posture kind %s is not mapped", k)
		}
	}
	if got := domain.OWASP("identity.ci_workload"); !slices.Equal(got, []string{"ASI03"}) {
		t.Errorf("identity recommendation: %v", got)
	}
	if got := domain.OWASP("export.siem"); len(got) != 0 {
		t.Errorf("export recommendation: %v", got)
	}
}

// TestEveryPostureKindHasItsOwnFix: every finding has a fix, and a new
// posture kind gets one here rather than the fallback.
// Covers: F861
func TestEveryPostureKindHasItsOwnFix(t *testing.T) {
	for _, k := range pdomain.Kinds {
		f := domain.PostureFix(string(k), "grant:x", "id")
		if f.Kind == domain.FixReviewFinding || f.Label == "" || f.TargetID != "grant:x" {
			t.Errorf("%s: %+v", k, f)
		}
	}
	if f := domain.PostureFix("new_kind", "", "id"); f.Kind != domain.FixReviewFinding || f.TargetID != "posture_finding:id" {
		t.Errorf("fallback: %+v", f)
	}
}

// TestFilterMatches covers every field, an agentless finding included.
// Covers: F860
// TestD256_UnknownAgeSortsLastAndSaysSo: within equal keys a finding with no
// known age follows every known age, and its reasons state that.
// Covers: F862
func TestD256_UnknownAgeSortsLastAndSaysSo(t *testing.T) {
	got := domain.Rank([]domain.Finding{
		{SourceID: "a-unknown", Severity: domain.SeverityHigh},
		{SourceID: "young", Severity: domain.SeverityHigh, Since: now.Add(-time.Hour)},
		{SourceID: "old", Severity: domain.SeverityHigh, Since: now.Add(-72 * time.Hour)},
		{SourceID: "low", Severity: domain.SeverityLow, Since: now.Add(-72 * time.Hour)},
	}, now)
	if want := []string{"old", "young", "a-unknown", "low"}; !slices.Equal(keys(got), want) {
		t.Fatalf("order %v, want %v", keys(got), want)
	}
	if r := got[2].RankReasons; !slices.Equal(r, []string{"severity:HIGH", domain.ReasonAgeUnknown}) {
		t.Errorf("reasons: %v", r)
	}
}

// TestD258_FixWithoutRemediation: a fix pointing at a source page stays, and
// one that could only reach a page that refuses has no target and says why.
// Covers: F861
func TestD258_FixWithoutRemediation(t *testing.T) {
	for _, k := range pdomain.Kinds {
		f := domain.PostureFix(string(k), "grant:x", "id")
		if got := f.WithoutRemediation(); got != f {
			t.Errorf("%s changed: %+v", k, got)
		}
	}
	for _, f := range []domain.Fix{
		domain.PostureFix("new_kind", "", "id"),
		{Kind: domain.FixReviewSuggested, TargetID: "suggestion:s", Label: "L"},
	} {
		got := f.WithoutRemediation()
		if got.Kind != domain.FixNone || !got.RequiresBusiness || got.TargetID != "" || got.Label == "" {
			t.Errorf("%+v: %+v", f, got)
		}
	}
}

func TestFilterMatches(t *testing.T) {
	a, b := ids.NewV7(), ids.NewV7()
	f := domain.Finding{
		Source: domain.SourcePosture, Kind: "k", Severity: domain.SeverityHigh, TeamID: &a, AgentID: &a, ConnectionID: &a,
	}
	for name, c := range map[string]struct {
		x    domain.Filter
		want bool
	}{
		"all":          {domain.Filter{}, true},
		"source":       {domain.Filter{Source: domain.SourceCoverage}, false},
		"kind":         {domain.Filter{Kind: "x"}, false},
		"severity":     {domain.Filter{Severity: domain.SeverityLow}, false},
		"team":         {domain.Filter{Team: &b}, false},
		"agent":        {domain.Filter{Agent: &b}, false},
		"connection":   {domain.Filter{Connection: &b}, false},
		"same":         {domain.Filter{Team: &a, Agent: &a, Connection: &a, Kind: "k"}, true},
		"agent absent": {domain.Filter{Agent: &a}, true},
	} {
		if got := c.x.Match(f); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if (domain.Filter{Agent: &a}).Match(domain.Finding{}) {
		t.Error("a finding with no agent matched an agent filter")
	}
}

// TestHR581_RollupClosedCounts: closed is what left since yesterday, a key
// that emptied keeps a row, and with yesterday not collected closed is
// absent, never zero.
// Covers: F865
func TestHR581_RollupClosedCounts(t *testing.T) {
	day := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	team := ids.NewV7()
	k := domain.DayKey{Kind: "k", Severity: domain.SeverityHigh, Team: team}
	gone := domain.DayKey{Kind: "gone", Severity: domain.SeverityLow}
	prev := []domain.DayCount{{DayKey: k, Open: 3}, {DayKey: gone, Open: 2}}
	fs := []domain.Finding{
		{Kind: "k", Severity: domain.SeverityHigh, TeamID: &team, Since: day.Add(-48 * time.Hour)},
		{Kind: "k", Severity: domain.SeverityHigh, TeamID: &team, Since: day.Add(time.Hour)}, // opened today
	}
	got := domain.Rollup(fs, day, prev, true)
	if len(got) != 2 {
		t.Fatalf("rows: %+v", got)
	}
	byKind := map[string]domain.DayCount{got[0].Kind: got[0], got[1].Kind: got[1]}
	if c := byKind["k"]; c.Open != 2 || c.Closed == nil || *c.Closed != 2 {
		t.Errorf("k: %+v", c)
	}
	if c := byKind["gone"]; c.Open != 0 || c.Closed == nil || *c.Closed != 2 {
		t.Errorf("gone: %+v", c)
	}
	for _, c := range domain.Rollup(fs, day, nil, false) {
		if c.Closed != nil {
			t.Errorf("closed with no day before: %+v", c)
		}
	}
}
