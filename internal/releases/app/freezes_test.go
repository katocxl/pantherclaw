// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/releases/app"
	"github.com/katocxl/pantherclaw/internal/releases/domain"
)

// TestDroppedFreezes: what a replacement or retirement lifts of a current
// or future freeze (G0 M11 D42a): past parts never count, a freeze still
// covered by the next window's freezes is not dropped, a shortened or
// split one is.
func TestDroppedFreezes(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return now.Add(time.Duration(h) * time.Hour) }
	span := func(a, b int) domain.Span { return domain.Span{Start: at(a), End: at(b)} }
	for _, c := range []struct {
		name      string
		old, next []domain.Span
		want      []domain.Span
	}{
		{"past only", []domain.Span{span(-10, -1)}, nil, nil},
		{"retired current", []domain.Span{span(-1, 5)}, nil, []domain.Span{span(0, 5)}},
		{"kept", []domain.Span{span(1, 5)}, []domain.Span{span(0, 6)}, nil},
		{"kept by two", []domain.Span{span(1, 5)}, []domain.Span{span(3, 6), span(0, 3)}, nil},
		{"shortened", []domain.Span{span(1, 5)}, []domain.Span{span(1, 3)}, []domain.Span{span(3, 5)}},
		{"gap", []domain.Span{span(1, 5)}, []domain.Span{span(1, 2), span(3, 5)}, []domain.Span{span(2, 3)}},
		{"two gaps", []domain.Span{span(1, 9)}, []domain.Span{span(2, 3), span(5, 6)}, []domain.Span{span(1, 2), span(3, 5), span(6, 9)}},
		{"moved later", []domain.Span{span(1, 5)}, []domain.Span{span(2, 6)}, []domain.Span{span(1, 2)}},
	} {
		got := app.DroppedFreezes(c.old, c.next, now)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if !got[i].Start.Equal(c.want[i].Start) || !got[i].End.Equal(c.want[i].End) {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
}
