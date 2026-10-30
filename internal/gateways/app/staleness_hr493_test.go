// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR493_GatewayCertificateChecksLiveOneSecond (ADR-0040, the gateway
// certificate cache): an entry answers for at most authTTL ≤ 1 s, and an
// org's notification forgets that org's entries only (HR-492).
// Covers: HR-493, HR-492
func TestHR493_GatewayCertificateChecksLiveOneSecond(t *testing.T) {
	if authTTL > time.Second {
		t.Fatalf("authTTL = %v, the bound is 1 s", authTTL)
	}
	c := newAuthCache()
	now := time.Now()
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	a := Identity{Org: org, Gateway: ids.NewV7(), Cert: ids.NewV7()}
	b := Identity{Org: other, Gateway: ids.NewV7(), Cert: ids.NewV7()}
	c.put(a, true, now, c.generation(org))
	c.put(b, true, now, c.generation(other))
	if ok, hit := c.get(a, now.Add(authTTL-time.Nanosecond)); !ok || !hit {
		t.Fatal("within the lifetime: a miss")
	}
	if _, hit := c.get(a, now.Add(authTTL)); hit {
		t.Fatal("served at the end of its lifetime")
	}
	c.forgetOrg(org)
	if _, hit := c.get(a, now); hit {
		t.Fatal("the notified org's entry was kept")
	}
	if _, hit := c.get(b, now); !hit {
		t.Fatal("another org's entry was forgotten")
	}
}

// TestHR493_ServerContainmentViewIsBounded (ADR-0040, the server's
// containment view per org): it is read at least every PollEvery (250 ms)
// and woken at once by LISTEN; a stream sends nothing confirmed more than
// ConfirmedWithin ago, both well inside the 2 s fail-closed bound (HR-010).
// Covers: HR-493
func TestHR493_ServerContainmentViewIsBounded(t *testing.T) {
	if PollEvery > 250*time.Millisecond || ConfirmedWithin > time.Second || PollEvery >= ConfirmedWithin {
		t.Fatalf("PollEvery %v, ConfirmedWithin %v", PollEvery, ConfirmedWithin)
	}
	h := NewHub(nil, nil)
	w := &orgWatch{gateways: map[ids.UUID]Containment{}}
	gw := ids.NewV7()
	now := time.Now()
	h.now = func() time.Time { return now }
	w.gateways[gw], w.confirmed = Containment{Epoch: 1, GatewayActive: true}, now
	s := &Subscription{hub: h, gateway: gw, w: w}
	if _, fresh := s.State(); !fresh {
		t.Fatal("a view just read is not fresh")
	}
	now = now.Add(ConfirmedWithin + time.Millisecond)
	if _, fresh := s.State(); fresh {
		t.Fatal("a view past ConfirmedWithin is still sent")
	}
}

// TestHR492_ACheckReadBeforeAForgetIsNotCached (D215): a check that began
// before its org was notified, or before a local revocation forgot an
// entry, is not cached when it finishes; a check of another org is.
// Covers: HR-492
func TestHR492_ACheckReadBeforeAForgetIsNotCached(t *testing.T) {
	c := newAuthCache()
	now := time.Now()
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	a := Identity{Org: org, Gateway: ids.NewV7(), Cert: ids.NewV7()}
	b := Identity{Org: other, Gateway: ids.NewV7(), Cert: ids.NewV7()}

	gen, otherGen := c.generation(org), c.generation(other)
	c.forgetOrg(org) // the notification arrives while both checks are read
	c.put(a, true, now, gen)
	if _, hit := c.get(a, now); hit {
		t.Fatal("a check read before the org's notification was cached")
	}
	c.put(b, true, now, otherGen)
	if _, hit := c.get(b, now); !hit {
		t.Fatal("another org's check was dropped")
	}

	for name, forget := range map[string]func(){
		"a certificate revoked here": func() { c.forget(a.Cert) },
		"a gateway revoked here":     func() { c.forgetGateway(a.Gateway) },
	} {
		gen := c.generation(org)
		forget()
		c.put(a, true, now, gen)
		if _, hit := c.get(a, now); hit {
			t.Fatalf("%s: a check read before it was cached", name)
		}
	}
	c.put(a, true, now, c.generation(org))
	if _, hit := c.get(a, now); !hit {
		t.Fatal("a check read after every forget was not cached")
	}
}
