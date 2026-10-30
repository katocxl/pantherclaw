// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR493_PermitKeysRefetchAtMostOnceASecond (ADR-0040, permit
// verification keys): a known key id is served from the cache; an unknown
// one refetches the JWKS once its last fetch is a second old, and never
// more often than that.
// Covers: HR-493
func TestHR493_PermitKeysRefetchAtMostOnceASecond(t *testing.T) {
	if jwksRefreshEvery > time.Second {
		t.Fatalf("jwksRefreshEvery = %v, the bound is 1 s", jwksRefreshEvery)
	}
	pv, j := verifierFixture(t)
	now := time.Now()
	pv.now = func() time.Time { return now }
	want := newWant()
	for range 3 {
		if _, err := pv.verify(context.Background(), j.sign(t, keys.PurposePermits, permitType, validClaims(want)), want); err != nil {
			t.Fatal(err)
		}
	}
	rotated := newRegistry(t)
	j.mu.Lock()
	j.reg = rotated
	j.mu.Unlock()
	tok := j.sign(t, keys.PurposePermits, permitType, validClaims(want))
	for range 3 {
		_, _ = pv.verify(context.Background(), tok, want)
	}
	now = now.Add(jwksRefreshEvery)
	if _, err := pv.verify(context.Background(), tok, want); err != nil {
		t.Fatalf("an unknown key id a second after the fetch: %v", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fetches != 2 {
		t.Fatalf("JWKS fetched %d times for 7 verifications across one rotation, want 2", j.fetches)
	}
}
