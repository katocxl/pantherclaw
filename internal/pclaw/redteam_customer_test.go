// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	rtapp "github.com/katocxl/pantherclaw/internal/redteam/app"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

type planReader struct {
	pantherclawv1connect.EntitlementServiceClient
	edition string
	err     error
}

func (p planReader) GetEntitlements(context.Context, *pantherclawv1.GetEntitlementsRequest) (*pantherclawv1.GetEntitlementsResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &pantherclawv1.GetEntitlementsResponse{Entitlements: &pantherclawv1.Entitlements{Edition: p.edition}}, nil
}

type rangeReader struct {
	pantherclawv1connect.RangeServiceClient
	res *pantherclawv1.GetRangeResponse
}

func (r rangeReader) GetRange(context.Context, *pantherclawv1.GetRangeRequest) (*pantherclawv1.GetRangeResponse, error) {
	return r.res, nil
}

func loaded(ids ...string) []rtapp.Loaded {
	out := make([]rtapp.Loaded, 0, len(ids))
	for _, id := range ids {
		out = append(out, rtapp.Loaded{Scenario: rtdomain.Scenario{ID: id, Title: id, Category: "boundary", Tier: "business"}, Digest: strings.Repeat("a", 64)})
	}
	return out
}

// TestRedteamCustomerSetsAreOneOrigin: a scenario directory holds library or
// customer scenarios, never both (G0 M17 D126).
// Covers: PN-009.6
func TestRedteamCustomerSetsAreOneOrigin(t *testing.T) {
	if o, err := setOrigin(loaded("CX-001", "CX-0002")); err != nil || o != rtdomain.OriginCustomer {
		t.Fatalf("customer set: %q %v", o, err)
	}
	if o, err := setOrigin(loaded("RT-001", "RT-002")); err != nil || o != rtdomain.OriginLibrary {
		t.Fatalf("library set: %q %v", o, err)
	}
	if _, err := setOrigin(loaded("CX-001", "RT-001")); err == nil {
		t.Fatal("a mixed set was accepted")
	}
}

// TestRedteamCustomerEditionIsCheckedEarly: below Business the CLI stops
// before a range starts; a plan it cannot read is left to the server.
// Covers: PN-009.6
func TestRedteamCustomerEditionIsCheckedEarly(t *testing.T) {
	for _, tc := range []struct {
		plan planReader
		ok   bool
	}{
		{planReader{edition: "community"}, false},
		{planReader{edition: "team"}, false},
		{planReader{edition: "business"}, true},
		{planReader{edition: "enterprise"}, true},
		{planReader{err: errors.New("permission_denied")}, true},
	} {
		err := checkCustomerEdition(t.Context(), clients{entitlements: tc.plan})
		if (err == nil) != tc.ok || (err != nil && !strings.Contains(err.Error(), "EDITION_REQUIRED")) {
			t.Errorf("%+v: %v", tc.plan, err)
		}
	}
	if err := checkCustomerEdition(t.Context(), clients{}); err != nil {
		t.Errorf("no plan client: %v", err)
	}
}

// TestRedteamCustomerBaselineIsAFinishedCustomerRange: --baseline-range
// names an earlier finished customer range with results (D126).
// Covers: PN-009.6
func TestRedteamCustomerBaselineIsAFinishedCustomerRange(t *testing.T) {
	finished := timestamppb.New(time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC))
	results := []*pantherclawv1.RangeResult{
		{ScenarioId: "CX-001", ScenarioDigest: strings.Repeat("a", 64), Verdict: pantherclawv1.RangeVerdict_RANGE_VERDICT_PASS},
		{ScenarioId: "CX-002", ScenarioDigest: strings.Repeat("b", 64), Verdict: pantherclawv1.RangeVerdict_RANGE_VERDICT_MISSING},
	}
	at := func(state pantherclawv1.RangeState, origin string, rs []*pantherclawv1.RangeResult) clients {
		return clients{ranges: rangeReader{res: &pantherclawv1.GetRangeResponse{
			Range: &pantherclawv1.Range{Id: rtRange, State: state, Origin: origin, FinishTime: finished}, Results: rs,
		}}}
	}
	b, err := loadRangeBaseline(t.Context(), at(pantherclawv1.RangeState_RANGE_STATE_FINISHED, "customer", results), rtRange)
	if err != nil {
		t.Fatal(err)
	}
	if b.rangeID != rtRange || b.finished != "2026-10-29T12:00:00Z" || len(b.entries) != 2 ||
		b.entries[0].Verdict != rtdomain.VerdictPass || b.entries[1].Verdict != rtdomain.VerdictMissing {
		t.Fatalf("baseline %+v", b)
	}
	for name, c := range map[string]clients{
		"running":       at(pantherclawv1.RangeState_RANGE_STATE_RUNNING, "customer", results),
		"library range": at(pantherclawv1.RangeState_RANGE_STATE_FINISHED, "library", results),
		"no results":    at(pantherclawv1.RangeState_RANGE_STATE_FINISHED, "customer", nil),
	} {
		if _, err := loadRangeBaseline(t.Context(), c, rtRange); err == nil || !strings.Contains(err.Error(), "BASELINE_INVALID") {
			t.Errorf("%s: %v, want BASELINE_INVALID", name, err)
		}
	}
	if _, err := loadRangeBaseline(t.Context(), at(pantherclawv1.RangeState_RANGE_STATE_FINISHED, "customer", results), "not-an-id"); err == nil {
		t.Error("a malformed range id was used")
	}
}

// TestRedteamCustomerSummaryIsMarkedCustomerAuthored: summary.json of a
// customer range says so, per range and per result, and makes no
// assurance claim (HR-466).
// Covers: PN-009.6
func TestRedteamCustomerSummaryIsMarkedCustomerAuthored(t *testing.T) {
	set := loaded("CX-001")
	res := []rtdomain.Result{{ScenarioID: "CX-001", Verdict: rtdomain.VerdictPass}}
	s := newSummary(rtRange, &pantherclawv1.Range{Id: rtRange, Origin: "customer"}, set, res, nil)
	if s.Origin != rtdomain.OriginCustomer || s.Statement != customerStatement || s.Results[0].Origin != rtdomain.OriginCustomer || !s.Unsigned {
		t.Fatalf("summary %+v", s)
	}
	if !strings.Contains(s.Statement, "Customer-authored") || !strings.Contains(s.Statement, "Not a PantherClaw-attested assurance report") {
		t.Fatalf("statement %q", s.Statement)
	}
	lib := newSummary(rtRange, &pantherclawv1.Range{Id: rtRange}, loaded("RT-001"), res, nil)
	if lib.Origin != rtdomain.OriginLibrary || lib.Statement != summaryStatement {
		t.Fatalf("library summary %+v", lib)
	}
}
