// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package audit_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
)

func TestOnceDeduplicatesWithinTheWindow(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	o := &audit.Once{Now: func() time.Time { return now }}
	if !o.First("a") || o.First("a") || !o.First("b") {
		t.Fatal("within the window")
	}
	now = now.Add(time.Minute)
	if !o.First("a") {
		t.Fatal("after the window")
	}
	for i := range audit.OnceEntries + 10 {
		o.First(strconv.Itoa(i))
	}
	if !o.First("b") {
		t.Fatal("the least recent key was not dropped")
	}
}
