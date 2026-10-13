// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"encoding/json/v2"
	"maps"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR203_TheExecutionReceiptCarriesTheAccess: an execution receipt
// records what the dispatch's minted credential allowed, as the gateway
// reported it (ADR-0021 item 5): the installation, the repository, the
// permissions requested and granted, the expiry and the revocation. A
// dispatch without one records none.
func TestHR203_TheExecutionReceiptCarriesTheAccess(t *testing.T) {
	f := setup(t, "1000", 0, 5*time.Second)
	ctx := context.Background()
	ev, _ := f.reg.Verifier(keys.PurposeReceipts, authority.TypeExecutionReceipt)
	type access struct {
		Installation int64             `json:"installation"`
		Repository   string            `json:"repository"`
		RepositoryID int64             `json:"repository_id"`
		Requested    map[string]string `json:"requested"`
		Granted      map[string]string `json:"granted"`
		ExpiresAt    string            `json:"expires_at"`
		Revocation   string            `json:"revocation"`
	}
	record := func(a *authority.Access) *access {
		t.Helper()
		res := f.authorize(t, "10.00")
		if _, err := f.svc.BeginDispatch(ctx, f.gw, res.PermitID, res.Epoch, authority.Outbound{}); err != nil {
			t.Fatal(err)
		}
		receipt, err := f.svc.RecordExecution(ctx, f.gw, authority.Execution{
			Permit: res.PermitID, Outcome: authority.Accepted, TargetStatus: 200, DispatchMS: 3, Access: a,
		})
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := ev.Verify(receipt)
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Pap struct {
				Access *access `json:"access"`
			} `json:"pap"`
		}
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		return claims.Pap.Access
	}
	expires := time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)
	perms := map[string]string{"contents": "write"}
	got := record(&authority.Access{
		Installation: 7, Repository: "acme/payments", RepositoryID: 42, Requested: perms, Granted: perms, Expires: expires, Revocation: "revoked",
	})
	if got == nil || got.Installation != 7 || got.Repository != "acme/payments" || got.RepositoryID != 42 || !maps.Equal(got.Requested, perms) ||
		!maps.Equal(got.Granted, perms) || got.ExpiresAt != "2026-10-11T13:00:00Z" || got.Revocation != "revoked" {
		t.Fatalf("access in the receipt: %+v", got)
	}
	if got := record(nil); got != nil {
		t.Fatalf("a static credential's receipt carries access %+v", got)
	}
}
