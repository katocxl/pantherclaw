// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

type recorded struct {
	name  string
	value float64
	attrs attribute.Set
}

type fakeHistogram struct {
	embedded.Float64Histogram
	name string
	got  *[]recorded
}

func (h fakeHistogram) Record(_ context.Context, v float64, opts ...metric.RecordOption) {
	*h.got = append(*h.got, recorded{name: h.name, value: v, attrs: metric.NewRecordConfig(opts).Attributes()})
}

func (h fakeHistogram) Enabled(context.Context) bool { return true }

type fakeMeter struct {
	noop.Meter
	got *[]recorded
}

func (m fakeMeter) Float64Histogram(name string, _ ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	return fakeHistogram{name: name, got: m.got}, nil
}

// TestT042_ServerHistogramsCarryNoOrg: closed entries are recorded with
// their kind and state only; an entry nobody answered has no first
// response, and an expired one no decision.
func TestT042_ServerHistogramsCarryNoOrg(t *testing.T) {
	var got []recorded
	h, err := NewHistograms(fakeMeter{got: &got})
	if err != nil {
		t.Fatal(err)
	}
	h.record(context.Background(), []dbq.ClosedEntriesBetweenRow{
		{Kind: "ACTION_HOLD", State: "APPROVED", FirstS: 30, DecisionS: 90},
		{Kind: "TOOL_REVIEW", State: "EXPIRED", FirstS: -1, DecisionS: 3600},
		{Kind: "ACCESS_REQUEST", State: "EXPIRED", FirstS: 10, DecisionS: 7200},
	})
	want := []recorded{
		{name: "pantherclaw.waitlist.first_response.duration", value: 30},
		{name: "pantherclaw.waitlist.decision.duration", value: 90},
		{name: "pantherclaw.waitlist.first_response.duration", value: 10},
	}
	if len(got) != len(want) {
		t.Fatalf("recorded %v", got)
	}
	for i, r := range got {
		if r.name != want[i].name || r.value != want[i].value {
			t.Fatalf("recorded %v", got)
		}
		var keys []string
		for _, kv := range r.attrs.ToSlice() {
			keys = append(keys, string(kv.Key))
		}
		if !slices.Equal(keys, []string{"kind", "state"}) {
			t.Fatalf("attributes %v", keys)
		}
	}
}
