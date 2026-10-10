// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"sync"
	"testing"

	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestRace_TwoApproversAtOnce: two eligible people approving a two-person
// requirement at the same moment each count once, and the request is
// approved once.
func TestRace_TwoApproversAtOnce(t *testing.T) {
	for range 5 {
		f := newFx(t, 2)
		req := f.request(2)
		people := []person{f.bob, f.dave}
		ceremonies := []ids.UUID{f.ceremony(f.bob, req), f.ceremony(f.dave, req)}
		var wg sync.WaitGroup
		errs := make([]error, len(people))
		for i, p := range people {
			wg.Go(func() {
				_, errs[i] = f.svc.Approve(context.Background(), f.org, approvals.Responder{User: p.id, Browser: p.browser}, req, approvals.Assertion{
					Ceremony: ceremonies[i], Credential: p.cred, AuthenticatorData: make([]byte, 37), ClientDataJSON: []byte(`{}`), Signature: []byte{1},
				})
			})
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("approver %d: %v", i, err)
			}
		}
		if s := f.str("SELECT state || ' ' || (SELECT count(*) FROM pc.approval_responses r WHERE r.request_id = q.id AND r.kind = 'APPROVE') FROM pc.approval_requests q WHERE id = $1", req); s != "APPROVED 2" {
			t.Fatalf("after two approvals at once: %s", s)
		}
		if s := f.str("SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.approval.approved'"); s != "1" {
			t.Fatalf("%s approved events", s)
		}
	}
}
