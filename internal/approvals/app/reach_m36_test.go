// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type failedReachEntitlements struct{ err error }

func (f failedReachEntitlements) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{}, f.err
}

func TestFatigueReportsEntitlementReadFailure(t *testing.T) {
	want := errors.New("entitlements unavailable")
	s := &Service{Ents: failedReachEntitlements{err: want}}
	if _, err := s.FlagFatigue(context.Background(), ids.New[ids.Org]()); !errors.Is(err, want) {
		t.Fatalf("FlagFatigue error = %v, want %v", err, want)
	}
}

// TestHR789_ReachPathsDoNotApprove: fatigue flagging without a Team
// licence writes nothing, and an unknown group is refused before any read
// of approval state.
// Covers: HR-789
func TestHR789_ReachPathsDoNotApprove(t *testing.T) {
	n, err := (&Service{}).FlagFatigue(context.Background(), ids.New[ids.Org]())
	if err != nil || n != 0 {
		t.Fatalf("flag without a licence: %d %v", n, err)
	}
	if _, err := (&Service{}).ListGroups(context.Background(), "PERSON", nil); !errors.Is(err, ErrGroupBy) {
		t.Fatalf("list groups: %v", err)
	}
}

// TestHR790_ADeputyWindowCannotNameThePersonOrRunPastThirtyDays: the
// bounds are refused before a row is written.
// Covers: HR-790
func TestHR790_ADeputyWindowCannotNameThePersonOrRunPastThirtyDays(t *testing.T) {
	org := ids.New[ids.Org]()
	user := ids.NewV7()
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
			Bindings: []td.Binding{{Role: td.RoleApprover, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		},
		Credential: tenancy.CredBrowserSession,
	})
	now := time.Now()
	_, err := (&Service{}).SetDeputy(ctx, nil, user, now, now.Add(time.Hour))
	if !errors.Is(err, ErrDeputyInvalid) {
		t.Fatalf("self deputy: %v", err)
	}
	_, err = (&Service{}).SetDeputy(ctx, nil, ids.NewV7(), now, now.Add(MaxDeputyWindow+time.Hour))
	if !errors.Is(err, ErrDeputyInvalid) {
		t.Fatalf("31-day window: %v", err)
	}
	_, err = (&Service{}).SetDeputy(ctx, nil, ids.NewV7(), now, now.Add(-time.Hour))
	if !errors.Is(err, ErrDeputyInvalid) {
		t.Fatalf("window already over: %v", err)
	}
}

// TestHR791_FatigueFlagsAreThresholdsOnly: each threshold flags, a count
// under it does not, and a decline keeps a perfect approve-share from flagging.
// Covers: HR-791
func TestHR791_FatigueFlagsAreThresholdsOnly(t *testing.T) {
	hour := &dbq.ApprovalFatigueRow{Approvals: FlagRateApprovals, TimedApprovals: FlagFastMinApprovals, MedianSeconds: FlagFastSeconds - 1}
	day := &dbq.ApprovalFatigueRow{Approvals: FlagNoDeclineApprovals, Declines: 0}
	got := fatigueReasons(hour, day)
	for _, reason := range []string{FlagApprovalRate, FlagFastApprovals, FlagNoDeclines} {
		if got[reason] == 0 {
			t.Errorf("missing %s in %v", reason, got)
		}
	}
	if _, ok := got["APPROVED"]; ok {
		t.Fatal("a fatigue measure approved")
	}
	under := fatigueReasons(&dbq.ApprovalFatigueRow{Approvals: FlagRateApprovals - 1, TimedApprovals: FlagFastMinApprovals - 1, MedianSeconds: FlagFastSeconds},
		&dbq.ApprovalFatigueRow{Approvals: FlagNoDeclineApprovals, Declines: 1})
	if len(under) != 0 {
		t.Fatalf("under the thresholds: %v", under)
	}
}

// TestT357_FatigueDoesNotRubberStamp: a streak with no declines raises a
// flag reason and nothing that would decide the hold.
// Covers: T-357
func TestT357_FatigueDoesNotRubberStamp(t *testing.T) {
	got := fatigueReasons(nil, &dbq.ApprovalFatigueRow{Approvals: 80, Declines: 0})
	if len(got) != 1 || got[FlagNoDeclines] != 80 {
		t.Fatalf("no-decline streak: %v", got)
	}
	if share(80, 0) != 1 || share(0, 0) != 0 {
		t.Fatalf("share = %v", share(80, 0))
	}
}
