// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestSilences: a gateway is a telemetry gap only for a stretch inside
// the run longer than its heartbeat window.
// Covers: F229
func TestSilences(t *testing.T) {
	gw := ids.NewV7()
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	h := time.Hour
	cases := []struct {
		name       string
		sightings  []time.Duration
		start, end time.Duration
		want       []time.Duration // gap times from t0
	}{
		{"renewed every day", []time.Duration{-2 * h, 22 * h, 46 * h, 70 * h}, 0, 72 * h, nil},
		{"silent in the middle", []time.Duration{-1 * h, 20 * h, 80 * h}, 0, 90 * h, []time.Duration{46 * h}},
		{"silent at the end", []time.Duration{-1 * h, 10 * h}, 0, 72 * h, []time.Duration{36 * h}},
		{"silent since before the run", []time.Duration{-30 * h, 40 * h}, 0, 50 * h, []time.Duration{0}},
		{"silence before the run only", []time.Duration{-80 * h, -10 * h, 10 * h, 30 * h}, 0, 40 * h, nil},
		{"sighting after the end", []time.Duration{-1 * h, 100 * h}, 0, 30 * h, []time.Duration{25 * h}},
	}
	for _, c := range cases {
		var s []time.Time
		for _, d := range c.sightings {
			s = append(s, t0.Add(d))
		}
		got := silences(gw, s, t0.Add(c.start), t0.Add(c.end))
		if len(got) != len(c.want) {
			t.Errorf("%s: %d gaps %+v, want %d", c.name, len(got), got, len(c.want))
			continue
		}
		for i, g := range got {
			if g.Kind != GapTelemetry || g.Gateway == nil || *g.Gateway != gw || !g.At.Equal(t0.Add(c.want[i])) {
				t.Errorf("%s: gap %d = %+v, want at %s", c.name, i, g, c.want[i])
			}
		}
	}
}

// TestTimelinePages: pages cover every event once, and a token works only
// for its own run.
// Covers: F224
func TestTimelinePages(t *testing.T) {
	run := ids.NewV7()
	tl := Timeline{Run: run}
	for i := range 450 {
		tl.Events = append(tl.Events, Event{At: time.Unix(int64(i), 0), Kind: EventDecision})
	}
	seen, tok := 0, ""
	for range 10 {
		var out Inspection
		if err := page(&out, tl, run, InspectOptions{PageToken: tok}); err != nil {
			t.Fatal(err)
		}
		if len(out.Events) > DefaultTimelinePage || !out.HasTimeline {
			t.Fatalf("page of %d", len(out.Events))
		}
		if len(out.Events) > 0 && !out.Events[0].At.Equal(time.Unix(int64(seen), 0)) {
			t.Fatalf("page starts at %s, want event %d", out.Events[0].At, seen)
		}
		seen += len(out.Events)
		if tok = out.NextPageToken; tok == "" {
			break
		}
	}
	if seen != 450 {
		t.Errorf("paged %d events, want 450", seen)
	}
	var out Inspection
	if err := page(&out, tl, run, InspectOptions{PageSize: 9999}); err != nil || len(out.Events) != 450 {
		t.Errorf("big page = %d, %v", len(out.Events), err)
	}
	for _, bad := range []string{"%%", pageToken(ids.NewV7(), 10), "eA"} {
		if err := page(&out, tl, run, InspectOptions{PageToken: bad}); !errors.Is(err, ErrBadPageToken) {
			t.Errorf("token %q: %v", bad, err)
		}
	}
}
