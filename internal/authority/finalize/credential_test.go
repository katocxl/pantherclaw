// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// credentialClaim is the pap.credential claim of an execution receipt, or
// nil when the receipt has none.
func credentialClaim(t *testing.T, receipt string) map[string]any {
	t.Helper()
	var r struct {
		Pap map[string]any `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(receipt), &r); err != nil {
		t.Fatal(err)
	}
	c, ok := r.Pap["credential"]
	if !ok {
		return nil
	}
	m, ok := c.(map[string]any)
	if !ok {
		t.Fatalf("credential claim %T %v", c, c)
	}
	return m
}

// TestHR660_TheReceiptNamesOnlyACheckedCredential: a reported credential
// lands in the receipt only when it is a version of the permit's
// connection's credential, in any state, and then as its id and version
// alone. Any other report is refused and leaves the permit dispatching; a
// dispatch that reports none gets no claim.
// Covers: F952
func TestHR660_TheReceiptNamesOnlyACheckedCredential(t *testing.T) {
	s, run, conn := enforced(t, finalize.AccessPantherClawHeld)
	ctx := context.Background()
	cred, other, otherConn := ids.NewV7(), ids.NewV7(), ids.NewV7()
	s.W.PutCredential(cred, conn, 1) // superseded by version 2: any state counts
	s.W.PutCredential(cred, conn, 2)
	s.W.PutCredential(other, otherConn, 1)

	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "30.00")))
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, outbound("{}")); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]finalize.CredentialUsed{
		"a version that never existed":      {ID: cred, Version: 3},
		"another connection's credential":   {ID: other, Version: 1},
		"an unknown credential":             {ID: ids.NewV7(), Version: 1},
		"another credential's version pair": {ID: other, Version: 2},
	} {
		_, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{
			Permit: res.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, Credential: &c,
		})
		if !errors.Is(err, finalize.ErrCredentialNotOfConnection) {
			t.Fatalf("%s: %v", name, err)
		}
		if st := s.W.PermitState(res.PermitID); st != "DISPATCHING" {
			t.Fatalf("%s: a refused report left the permit %s", name, st)
		}
	}
	r, err := s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{
		Permit: res.PermitID, Outcome: finalize.Accepted, TargetStatus: 200,
		Credential: &finalize.CredentialUsed{ID: cred, Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := credentialClaim(t, r)
	if len(c) != 2 || c["id"] != cred.String() || c["version"] != float64(1) {
		t.Fatalf("credential claim %v, want only id %s and version 1", c, cred)
	}

	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_2", "30.00")))
	if _, err := s.Authority.BeginDispatch(ctx, s.Gateway, res.PermitID, res.Epoch, outbound("{}")); err != nil {
		t.Fatal(err)
	}
	r, err = s.Authority.RecordExecution(ctx, s.Gateway, finalize.Execution{Permit: res.PermitID, Outcome: finalize.Failed})
	if err != nil {
		t.Fatal(err)
	}
	if c := credentialClaim(t, r); c != nil {
		t.Fatalf("no credential reported, yet the receipt names %v", c)
	}
}
