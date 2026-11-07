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
// across keys, a tracked key over the cap is counted on itself, and an
// untracked one on the org.
func TestHR850_RefusalLimiter(t *testing.T) {
	var r refusals
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if ok, n, _ := r.take(org, "instance:i1|proof_replay", t0); !ok || n != 0 {
		t.Fatalf("first: %t %d", ok, n)
	}
	for i := range 4 {
		if ok, _, _ := r.take(org, "instance:i1|proof_replay", t0.Add(time.Duration(i+1)*time.Second)); ok {
			t.Fatal("a second record within the minute")
		}
	}
	if ok, _, _ := r.take(org, "instance:i1|key_mismatch", t0); !ok {
		t.Error("another code shares the window")
	}
	if ok, _, _ := r.take(other, "instance:i1|proof_replay", t0); !ok {
		t.Error("another org shares the window")
	}
	if ok, n, _ := r.take(org, "instance:i1|proof_replay", t0.Add(RefusalWindow)); !ok || n != 4 {
		t.Fatalf("after the window: %t, suppressed %d, want 4", ok, n)
	}

	// The per-org cap across made-up keys: a key the limiter already
	// tracks counts its own refusals over the cap.
	var c refusals
	for i := range MaxRefusalRecordsPerOrg {
		if ok, _, _ := c.take(org, "key:"+strconv.Itoa(i), t0); !ok {
			t.Fatalf("key %d under the cap was not recorded", i)
		}
	}
	t1 := t0.Add(RefusalWindow)
	for i := range MaxRefusalRecordsPerOrg {
		if ok, _, _ := c.take(org, "key:x"+strconv.Itoa(i), t1); !ok {
			t.Fatalf("fresh key %d in the next window was not recorded", i)
		}
	}
	if ok, _, _ := c.take(org, "key:0", t1); ok {
		t.Fatal("a record over the org cap")
	}
	if ok, n, _ := c.take(org, "key:0", t1.Add(RefusalWindow)); !ok || n != 1 {
		t.Fatalf("the tracked key next window: %t, suppressed %d, want 1", ok, n)
	}
}

// TestHR850_RefusalLimiterStaysBounded: 70 distinct made-up keys within a
// minute record 60, add at most 60 entries, and the next window's first
// record carries the 10 untracked refusals as org_suppressed.
func TestHR850_RefusalLimiterStaysBounded(t *testing.T) {
	var r refusals
	org := ids.New[ids.Org]()
	t0 := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	recorded := 0
	for i := range 70 {
		if ok, _, _ := r.take(org, "key:made-up-"+strconv.Itoa(i)+"|invalid_proof", t0.Add(time.Duration(i)*time.Millisecond)); ok {
			recorded++
		}
	}
	if recorded != MaxRefusalRecordsPerOrg || len(r.keys) > MaxRefusalRecordsPerOrg {
		t.Fatalf("recorded %d, key entries %d; want %d and at most %d", recorded, len(r.keys), MaxRefusalRecordsPerOrg, MaxRefusalRecordsPerOrg)
	}
	ok, n, orgN := r.take(org, "key:another|invalid_proof", t0.Add(RefusalWindow))
	if !ok || n != 0 || orgN != 10 {
		t.Fatalf("next window: %t, suppressed %d, org_suppressed %d; want true, 0, 10", ok, n, orgN)
	}
	if ok, _, orgN := r.take(org, "key:yet-another|invalid_proof", t0.Add(RefusalWindow)); !ok || orgN != 0 {
		t.Fatalf("org_suppressed is carried once: %t, %d", ok, orgN)
	}

	// A full map: an untracked key is recorded (the org cap still bounds
	// records) but never added.
	var f refusals
	f.keys, f.orgs = map[string]refusalSlot{}, map[ids.OrgID]orgSlot{}
	for i := range maxRefusalKeys {
		f.keys["held-"+strconv.Itoa(i)] = refusalSlot{at: t0, n: 1}
	}
	if ok, _, _ := f.take(org, "key:new|invalid_proof", t0); !ok || len(f.keys) > maxRefusalKeys {
		t.Fatalf("full map: %t, %d entries", ok, len(f.keys))
	}
}
