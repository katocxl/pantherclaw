// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR850_RefusalLimiter: one record per org, key and code a minute; the
// refusals in between ride on the next record; an org's records are capped
// across keys, and the capped ones are counted on their own key.
func TestHR850_RefusalLimiter(t *testing.T) {
	var r refusals
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if ok, n := r.take(org, "instance:i1|proof_replay", t0); !ok || n != 0 {
		t.Fatalf("first: %t %d", ok, n)
	}
	for i := range 4 {
		if ok, _ := r.take(org, "instance:i1|proof_replay", t0.Add(time.Duration(i+1)*time.Second)); ok {
			t.Fatal("a second record within the minute")
		}
	}
	if ok, _ := r.take(org, "instance:i1|key_mismatch", t0); !ok {
		t.Error("another code shares the window")
	}
	if ok, _ := r.take(other, "instance:i1|proof_replay", t0); !ok {
		t.Error("another org shares the window")
	}
	if ok, n := r.take(org, "instance:i1|proof_replay", t0.Add(RefusalWindow)); !ok || n != 4 {
		t.Fatalf("after the window: %t, suppressed %d, want 4", ok, n)
	}

	// The per-org cap across made-up keys.
	var c refusals
	for i := range MaxRefusalRecordsPerOrg {
		if ok, _ := c.take(org, "key:"+strconv.Itoa(i), t0); !ok {
			t.Fatalf("key %d under the cap was not recorded", i)
		}
	}
	if ok, _ := c.take(org, "key:capped", t0); ok {
		t.Fatal("a record over the org cap")
	}
	if ok, n := c.take(org, "key:capped", t0.Add(RefusalWindow)); !ok || n != 1 {
		t.Fatalf("the capped key next window: %t, suppressed %d, want 1", ok, n)
	}
}
