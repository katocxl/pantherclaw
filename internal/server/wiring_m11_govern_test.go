// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/promotions"
)

// TestHR290_TheProductionGrantsStoreAndServiceHaveTheGate (D81): the API's
// grants store, which issues and revises in its transaction, and the
// grants service, which automation issuance and the provisional expiry
// cap go through, both carry the promotion gate with what a prefix and
// the cap need. (Integration fixtures that build their own store test the
// grants themselves, not the gate.)
func TestHR290_TheProductionGrantsStoreAndServiceHaveTheGate(t *testing.T) {
	store, svc := newGrants(&db.Pool{})
	for name, g := range map[string]any{"store": store.Promotions, "service": svc.Promotions} {
		gate, ok := g.(promotions.Gate)
		if !ok {
			t.Fatalf("the %s's gate is %T, want promotions.Gate", name, g)
		}
		if gate.Packages == nil {
			t.Errorf("the %s's gate cannot expand prefixes", name)
		}
		if gate.Pool == nil {
			t.Errorf("the %s's gate cannot cap grants under provisional promotions (D80)", name)
		}
	}
	if svc.Repo != store {
		t.Error("the service does not issue through the gated store")
	}
}
