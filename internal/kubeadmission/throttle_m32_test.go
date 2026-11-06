// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kubeadmission

import (
	"strconv"
	"testing"
	"time"
)

// TestHR735_TheThrottleNeverDropsADenyAuditAndStaysBounded: a key passes
// once a minute; a second key in the same minute passes on its own; past
// the cap every new key still passes (its audit is written) without being
// remembered, so the throttle holds at most twice the cap; keys are
// forgotten two rotations later, never sooner than a minute (D1218 item 3).
func TestHR735_TheThrottleNeverDropsADenyAuditAndStaysBounded(t *testing.T) {
	const limit = 100
	th := newThrottle(time.Minute, limit)
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	if pass, _ := th.take("ns|K8S_EDGE_MISSING", now); !pass {
		t.Fatal("a first deny was throttled")
	}
	if pass, _ := th.take("ns|K8S_EDGE_MISSING", now.Add(30*time.Second)); pass {
		t.Error("the same code in the same minute passed again")
	}
	if pass, _ := th.take("ns|K8S_POD_ESCAPE", now.Add(30*time.Second)); !pass {
		t.Error("a second code in the same minute was throttled")
	}
	overflowed := 0
	for i := range 3 * limit {
		pass, over := th.take("fresh|"+strconv.Itoa(i), now.Add(40*time.Second))
		if !pass {
			t.Fatalf("fresh key %d was throttled", i)
		}
		if over {
			overflowed++
		}
	}
	if overflowed == 0 || th.size() > 2*limit {
		t.Errorf("past the cap: %d overflowed, size %d (cap %d)", overflowed, th.size(), limit)
	}
	// A minute after the first take: rotated, but the key taken at +30s is
	// still within its minute.
	if pass, _ := th.take("ns|K8S_POD_ESCAPE", now.Add(70*time.Second)); pass {
		t.Error("a key passed again within its minute after a rotation")
	}
	if pass, _ := th.take("ns|K8S_EDGE_MISSING", now.Add(70*time.Second)); !pass {
		t.Error("a key was still throttled a minute later")
	}
	for i := range 3 * limit {
		if pass, _ := th.take("later|"+strconv.Itoa(i), now.Add(80*time.Second)); !pass {
			t.Fatalf("later key %d was throttled", i)
		}
	}
	if th.size() > 2*limit {
		t.Errorf("after a rotation the throttle holds %d keys (cap %d)", th.size(), limit)
	}
	// Both generations old: everything is forgotten.
	if pass, _ := th.take("ns|K8S_POD_ESCAPE", now.Add(5*time.Minute)); !pass || th.size() != 1 {
		t.Errorf("five minutes later: pass %v, size %d", pass, th.size())
	}
	// A clock that goes back forgets rather than throttles forever.
	if pass, _ := th.take("ns|K8S_POD_ESCAPE", now); !pass {
		t.Error("after the clock went back a key was throttled")
	}
	// A failed write frees its key.
	at := now.Add(10 * time.Minute)
	th.take("ns|K8S_NO_ISSUER", at)
	th.release("ns|K8S_NO_ISSUER", at)
	if pass, _ := th.take("ns|K8S_NO_ISSUER", at.Add(time.Second)); !pass {
		t.Error("a released key was throttled")
	}
	// A key taken before a rotation is in the previous generation when its
	// write fails; releasing it frees it there too (D1218a R1).
	th.take("ns|K8S_POD_ESCAPE", at.Add(50*time.Second))
	th.take("ns|other", at.Add(61*time.Second)) // rotates
	th.release("ns|K8S_POD_ESCAPE", at.Add(50*time.Second))
	if pass, _ := th.take("ns|K8S_POD_ESCAPE", at.Add(62*time.Second)); !pass {
		t.Error("a key released after a rotation was throttled")
	}
}
