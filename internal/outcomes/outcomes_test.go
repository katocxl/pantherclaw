// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package outcomes

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var testEnd = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

func testWindow() Window { return windowOf(testEnd, 7) }

func reasonOf(reasons []Reason, code string) (Reason, bool) {
	i := slices.IndexFunc(reasons, func(r Reason) bool { return r.Code == code })
	if i < 0 {
		return Reason{}, false
	}
	return reasons[i], true
}

// TestHR537_NothingMeasuredHasNoValue: a window with no measured case has
// no value and says why. Zero seconds or a zero share is a measured result,
// so it never stands in for "not collected".
// Covers: F774
func TestHR537_NothingMeasuredHasNoValue(t *testing.T) {
	w := testWindow()
	for name, s := range map[string]Sample{
		"duration": duration(MetricApprovalWait, "", w, nil, nil),
		"share":    share(MetricHoldShare, "", w, 0, 0, nil),
	} {
		if s.Collected() || s.P50 != nil || s.P90 != nil || s.Share != nil {
			t.Fatalf("%s: a window with nothing measured has a value: %+v", name, s)
		}
		if _, ok := reasonOf(s.Reasons, ReasonNoMeasurableCase); !ok {
			t.Fatalf("%s: no reason stated: %+v", name, s.Reasons)
		}
	}
	// A measured zero is collected, so the two never look alike.
	if s := share(MetricHoldShare, "", w, 0, 12, nil); !s.Collected() || s.Share == nil || *s.Share != 0 {
		t.Fatalf("a measured zero: %+v", s)
	}
	if s := duration(MetricApprovalWait, "", w, []float64{0}, nil); !s.Collected() || s.P50 == nil {
		t.Fatalf("a measured zero duration: %+v", s)
	}
	// What was unmeasured is the reason, and stays countable.
	s := duration(MetricApprovalWait, "", w, nil, []Reason{reasonWith(ReasonOpenWaiting, 3, 60)})
	if s.Collected() || s.Unmeasured != 3 {
		t.Fatalf("open cases: %+v", s)
	}
	if _, ok := reasonOf(s.Reasons, ReasonNoMeasurableCase); ok {
		t.Fatalf("a window with open cases says nothing was measurable: %+v", s.Reasons)
	}
}

// TestHR537_ABackfillIsNotCollected: a window that began before collection
// started is not collected for every metric, whatever the records hold.
// Covers: F774
func TestHR537_ABackfillIsNotCollected(t *testing.T) {
	w := testWindow()
	ss, err := sampleWindow(t.Context(), nil, ids.OrgID{}, w.Start.Add(time.Second), w)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) != len(Definitions) {
		t.Fatalf("%d samples for %d metrics", len(ss), len(Definitions))
	}
	for _, s := range ss {
		if s.Collected() || s.finish().Reasons[0].Code != ReasonCollectionNotStarted {
			t.Fatalf("%s: %+v", s.Metric, s)
		}
	}
}

// TestHR538_ARequestIsNotAConfirmation: only a confirmed time counts. A
// requested action, a failed or unsupported one, a declared incident and a
// reason that no containment is needed each leave the case unmeasured, under
// their own reason.
// Covers: F774
func TestHR538_ARequestIsNotAConfirmation(t *testing.T) {
	w := testWindow()
	started := w.End.Add(-48 * time.Hour)
	confirmed := w.End.Add(-47 * time.Hour)
	for _, tc := range []struct {
		name string
		e    Episode
		want string
	}{
		{"requested", Episode{Started: started, OpenRequests: 1}, ReasonRequestedNotConfirmed},
		{"failed", Episode{Started: started, Failed: 1}, ReasonFailedOrUnsupported},
		{"declared", Episode{Started: started, Declared: true}, ReasonDeclaredNotConfirmed},
		{"declared with a request", Episode{Started: started, Declared: true, OpenRequests: 1}, ReasonRequestedNotConfirmed},
		{"no containment needed", Episode{Started: started, NoContainmentNeeded: true}, ReasonNoContainmentNeeded},
		{"nothing done", Episode{Started: started}, ReasonOpenNotContained},
	} {
		seconds, reasons := episodes(w, []Episode{tc.e})
		if len(seconds) != 0 {
			t.Fatalf("%s was counted as contained: %v", tc.name, seconds)
		}
		if r, ok := reasonOf(reasons, tc.want); !ok || r.Count != 1 {
			t.Fatalf("%s: %+v", tc.name, reasons)
		}
	}
	seconds, reasons := episodes(w, []Episode{{Started: started, Confirmed: &confirmed, OpenRequests: 1}})
	if !slices.Equal(seconds, []float64{3600}) || len(reasons) != 0 {
		t.Fatalf("a confirmed case: %v %+v", seconds, reasons)
	}
	// Confirmed after the window ended: it was still unconfirmed at the end.
	late := w.End.Add(time.Hour)
	if seconds, reasons := episodes(w, []Episode{{Started: started, Confirmed: &late, OpenRequests: 1}}); len(seconds) != 0 || len(reasons) != 1 {
		t.Fatalf("confirmed later: %v %+v", seconds, reasons)
	}
	// Confirmed before it was opened has no honest duration, not a 0.
	before := started.Add(-time.Minute)
	// Confirmed before the window: it belongs to an earlier one.
	early := w.Start.Add(-time.Hour)
	if seconds, reasons := episodes(w, []Episode{{Started: early.Add(-time.Hour), Confirmed: &early}}); len(seconds) != 0 || len(reasons) != 0 {
		t.Fatalf("an old confirmation: %v %+v", seconds, reasons)
	}
	// Ended unconfirmed in the window: listed, not contained.
	inside := w.Start.Add(time.Hour)
	if seconds, reasons := episodes(w, []Episode{{Started: inside, Ended: true}}); len(seconds) != 0 || len(reasons) != 1 {
		t.Fatalf("ended unconfirmed inside: %v %+v", seconds, reasons)
	}
	if seconds, reasons := episodes(w, []Episode{{Started: started, Confirmed: &before}}); len(seconds) != 0 || len(reasons) != 1 {
		t.Fatalf("confirmed in the window, before it opened: %v %+v", seconds, reasons)
	}
}

// TestHR539_NoMetricIsARawVolume: every metric is a distribution or a share,
// and no definition claims time saved or any other value from a volume.
// Covers: F774
func TestHR539_NoMetricIsARawVolume(t *testing.T) {
	claims := regexp.MustCompile(`(?i)\b(saved|savings|roi|productivity|value delivered)\b`)
	for _, d := range Definitions {
		if d.Kind != KindDuration && d.Kind != KindShare {
			t.Fatalf("%s is a %q", d.Name, d.Kind)
		}
		if strings.Contains(d.Name, "count") || strings.Contains(d.Name, "total") {
			t.Fatalf("%s is named as a volume", d.Name)
		}
		if strings.Contains(strings.ToLower(d.Title), "number of") {
			t.Fatalf("%s is titled as a volume", d.Name)
		}
		measures := strings.ReplaceAll(d.Measures, "No time saved is claimed.", "")
		if claims.MatchString(d.Title) || claims.MatchString(measures) {
			t.Fatalf("%s claims value: %q", d.Name, d.Measures)
		}
	}
	// A duration holds seconds and a share a ratio; the case count is only
	// ever the denominator beside them.
	if s := share(MetricHoldShare, "", testWindow(), 500, 1000, nil); s.Share == nil || *s.Share != 0.5 || s.P50 != nil {
		t.Fatalf("share: %+v", s)
	}
	if s := duration(MetricApprovalWait, "", testWindow(), []float64{1, 2, 3}, nil); s.P50 == nil || *s.P50 != 2 || s.Share != nil {
		t.Fatalf("duration: %+v", s)
	}
}

// TestHR540_EveryDefinitionStatesWhatItCannotSee: every metric is complete,
// states what it cannot see, names its sources' permissions and belongs to
// one of the six; together they cover all six.
// Covers: F774
func TestHR540_EveryDefinitionStatesWhatItCannotSee(t *testing.T) {
	groups := map[string]bool{}
	seen := map[string]bool{}
	name := regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	for _, d := range Definitions {
		if !name.MatchString(d.Name) || seen[d.Name] {
			t.Fatalf("bad or repeated name %q", d.Name)
		}
		seen[d.Name] = true
		groups[d.Group] = true
		if d.Title == "" || d.Measures == "" || len(d.NotSeen) == 0 || len(d.Reads) == 0 {
			t.Fatalf("%s is incomplete: %+v", d.Name, d)
		}
	}
	for _, g := range []string{"M1", "M2", "M3", "M4", "M5", "M6"} {
		if !groups[g] {
			t.Fatalf("no metric for %s", g)
		}
	}
}

// TestF774_DefinitionsStayDrafts: every definition stays a draft until the
// founder signs it off in the M21 brief (G17).
// Covers: F774
func TestF774_DefinitionsStayDrafts(t *testing.T) {
	for _, d := range Definitions {
		if d.Status != DefinitionDraft {
			t.Fatalf("%s: %q", d.Name, d.Status)
		}
	}
}

// TestF774_OutcomeMetricsNeedBusiness: D303.
// Covers: F774
func TestF774_OutcomeMetricsNeedBusiness(t *testing.T) {
	for ed, want := range map[billing.Edition]bool{
		billing.Community: false, billing.Team: false, billing.Business: true, billing.Enterprise: true,
	} {
		if got := (billing.Entitlements{Edition: ed}).OutcomeMetrics(); got != want {
			t.Fatalf("%s: %v", ed, got)
		}
	}
}

// TestF774_Percentiles interpolates as percentile_cont does.
// Covers: F774
func TestF774_Percentiles(t *testing.T) {
	s := duration(MetricApprovalWait, "", testWindow(), []float64{40, 10, 30, 20}, nil)
	if *s.P50 != 25 || *s.P90 != 37 {
		t.Fatalf("%v %v", *s.P50, *s.P90)
	}
	if s := duration(MetricApprovalWait, "", testWindow(), []float64{7}, nil); *s.P50 != 7 || *s.P90 != 7 {
		t.Fatalf("one case: %v %v", *s.P50, *s.P90)
	}
}

// TestF774_AgentJourneys: M1 counts an agent in the window of its first
// enforced decision and keeps it open, with its age, until it has one.
// Covers: F774
func TestF774_AgentJourneys(t *testing.T) {
	w := testWindow()
	enrolled := w.Start.Add(-time.Hour)
	inside := w.Start.Add(time.Hour)
	old := w.Start.Add(-time.Minute)
	seconds, reasons := journeys(w, []JourneyCase{
		{Enrolled: enrolled, Enforced: &inside},
		{Enrolled: enrolled},
		{Enrolled: enrolled, Observed: true},
		{Enrolled: enrolled.Add(-time.Hour), Enforced: &old},
		{Enrolled: w.End.Add(time.Hour)},
	})
	if !slices.Equal(seconds, []float64{7200}) {
		t.Fatalf("seconds: %v", seconds)
	}
	r, ok := reasonOf(reasons, ReasonOpenNoEnforcedDecision)
	if !ok || r.Count != 1 || *r.OldestAgeSeconds != w.End.Sub(enrolled).Seconds() {
		t.Fatalf("open: %+v", reasons)
	}
	if r, ok := reasonOf(reasons, ReasonRouteNeverEnforced); !ok || r.Count != 1 {
		t.Fatalf("observed: %+v", reasons)
	}
}

// TestF774_ReasonsTotalTheUnmeasured: the unmeasured count is the reasons'.
// Covers: F774
func TestF774_ReasonsTotalTheUnmeasured(t *testing.T) {
	s := share(MetricOverrideShare, "", testWindow(), 1, 4, []Reason{{Code: ReasonFollowUpRunning, Count: 3}, {Code: ReasonEmergencyChange}})
	if s.Unmeasured != 3 || len(s.Reasons) != 1 {
		t.Fatalf("%+v", s)
	}
}
