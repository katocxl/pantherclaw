// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

// TestHR222_SimulatedTransactionsAreFlaggedForTheWaitlistBanner: of two
// transactions, exactly the range run's is reported simulated, so a console
// shows a SIMULATED banner on its waitlist entries (F630).
func TestHR222_SimulatedTransactionsAreFlaggedForTheWaitlistBanner(t *testing.T) {
	f := newWFx(t)
	sim := ids.NewV7()
	f.exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state, simulated)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK', 'gw', 'OPEN', true)`, f.org, sim, f.run, ids.NewV7(), make([]byte, 32))
	got, err := waitlist.NewReader(f.p).SimulatedTransactions(f.as(f.ann, td.RoleOrgAdmin), []ids.UUID{f.txn, sim})
	if err != nil || len(got) != 1 || !got[sim] || got[f.txn] {
		t.Fatalf("SimulatedTransactions = %v, %v, want only %s", got, err, sim)
	}
}
