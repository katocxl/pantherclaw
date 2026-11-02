// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func txn(op, decision string) domain.Transaction {
	return domain.Transaction{ID: ids.NewV7(), Operation: op, Decision: decision, Mode: "enforce", Simulated: true, Reason: "R"}
}

// TestHR608_OutcomesComeFromTheServersRecords: each decision gives its
// outcome, and nothing the runner says is an input.
// Covers: F901
func TestHR608_OutcomesComeFromTheServersRecords(t *testing.T) {
	a := domain.Attempt{ID: "merge", Boundary: "HR-201", Expected: domain.ExpectHeld, Operation: "github.pulls.merge"}
	for decision, want := range map[string]domain.Outcome{
		"REQUIRE_APPROVAL": domain.Held, "REQUIRE_STEP_UP": domain.Held, "DENY": domain.Denied, "CANNOT_AUTHORIZE": domain.Denied,
		"ALLOW": domain.Allowed, "ALLOW_WITH_OBLIGATIONS": domain.Allowed,
	} {
		st := domain.Derive("RT-140", a, []domain.Transaction{txn(a.Operation, decision)}, nil)
		if st.Outcome != want || st.Basis != domain.ServerRecord || st.Transaction == nil {
			t.Errorf("%s: %+v, want %s from the server's record", decision, st, want)
		}
	}
}

// TestHR608_AWorseRecordIsNeverHidden: a denied retry after an allowed call
// is ALLOWED; monitor mode stopped nothing; a held action with an effect went
// through; and a real transaction never counts.
// Covers: F901
func TestHR608_AWorseRecordIsNeverHidden(t *testing.T) {
	a := domain.Attempt{ID: "merge", Boundary: "HR-201", Expected: domain.ExpectHeld, Operation: "op.x"}
	if st := domain.Derive("RT-140", a, []domain.Transaction{txn("op.x", "ALLOW"), txn("op.x", "DENY")}, nil); st.Outcome != domain.Allowed {
		t.Errorf("allowed then denied: %s", st.Outcome)
	}
	if st := domain.Derive("RT-140", a, []domain.Transaction{txn("op.x", "DENY"), txn("op.x", "REQUIRE_APPROVAL")}, nil); st.Outcome != domain.Held {
		t.Errorf("denied then held: %s", st.Outcome)
	}
	mon := txn("op.x", "DENY")
	mon.Mode = "monitor"
	if st := domain.Derive("RT-140", a, []domain.Transaction{mon}, nil); st.Outcome != domain.Allowed {
		t.Errorf("a monitor-mode deny stops nothing: %s", st.Outcome)
	}
	ran := txn("op.x", "REQUIRE_APPROVAL")
	ran.Effect = "CONFIRMED"
	if st := domain.Derive("RT-140", a, []domain.Transaction{ran}, nil); st.Outcome != domain.Allowed {
		t.Errorf("a held action with an effect: %s", st.Outcome)
	}
	none := txn("op.x", "REQUIRE_APPROVAL")
	none.Effect = "NONE_CONFIRMED"
	if st := domain.Derive("RT-140", a, []domain.Transaction{none}, nil); st.Outcome != domain.Held {
		t.Errorf("a held action with no effect: %s", st.Outcome)
	}
	prod := txn("op.x", "DENY")
	prod.Simulated = false
	if st := domain.Derive("RT-140", a, []domain.Transaction{prod}, nil); st.Outcome != domain.NotExercised {
		t.Errorf("a real transaction backs nothing: %s", st.Outcome)
	}
}

// TestHR609_NotExercisedIsAGap: without a record or a report the attempt is
// NOT_EXERCISED, whatever else happened in the run.
// Covers: F902
func TestHR609_NotExercisedIsAGap(t *testing.T) {
	a := domain.Attempt{ID: "merge", Boundary: "HR-201", Expected: domain.ExpectDenied, Operation: "op.x", RouteHost: "evil.example"}
	st := domain.Derive("RT-140", a, []domain.Transaction{txn("op.other", "DENY")}, []domain.Route{{Kind: domain.RouteDirectAPI, Locator: "other.example:443"}})
	if st.Outcome != domain.NotExercised || st.Basis != domain.NoBasis || st.Transaction != nil {
		t.Fatalf("%+v", st)
	}
	if c := domain.Count([]domain.Step{st}); c.NotExercised != 1 || c.Denied+c.Held+c.NotRoutedReported != 0 {
		t.Fatalf("a gap counted as held: %+v", c)
	}
}

// TestHR610_ARouteReportStaysAReport: an edge report is labelled as one, and
// the server's record wins over it.
// Covers: F903
func TestHR610_ARouteReportStaysAReport(t *testing.T) {
	a := domain.Attempt{ID: "exfil", Boundary: "HR-214", Expected: domain.ExpectNotRouted, Operation: "op.x", RouteHost: "evil.example"}
	route := []domain.Route{{Kind: domain.RouteDirectAPI, Locator: "EVIL.example:443"}}
	st := domain.Derive("RT-141", a, nil, route)
	if st.Outcome != domain.NotRoutedReported || st.Basis != domain.EdgeReport || st.Route == "" || st.Transaction != nil {
		t.Fatalf("%+v", st)
	}
	if st := domain.Derive("RT-141", a, []domain.Transaction{txn("op.x", "ALLOW")}, route); st.Outcome != domain.Allowed {
		t.Fatalf("a report hid an allowed record: %+v", st)
	}
	bait := domain.Attempt{ID: "bait", Boundary: "HR-214", Expected: domain.ExpectNotRouted, Credential: true}
	if st := domain.Derive("RT-144", bait, nil, []domain.Route{{Kind: domain.RouteCredential, Locator: "github_pat:abc"}}); st.Outcome != domain.NotRoutedReported {
		t.Fatalf("stripped credential: %+v", st)
	}
	if st := domain.Derive("RT-144", a, nil, []domain.Route{{Kind: domain.RouteCredential, Locator: "github_pat:abc"}}); st.Outcome != domain.NotExercised {
		t.Fatalf("a credential route is no destination: %+v", st)
	}
}

// TestHR611_RunsBelongToTheTwin: only a simulated run of the twin made after
// the start backs a campaign.
// Covers: F900
func TestHR611_RunsBelongToTheTwin(t *testing.T) {
	agent, start := ids.NewV7(), time.Now()
	ok := domain.RunRecord{Agent: agent, Simulated: true, Created: start}
	if !ok.Belongs(agent, start) {
		t.Fatal("the twin's run")
	}
	for name, r := range map[string]domain.RunRecord{
		"real":    {Agent: agent, Created: start},
		"another": {Agent: ids.NewV7(), Simulated: true, Created: start},
		"earlier": {Agent: agent, Simulated: true, Created: start.Add(-time.Second)},
	} {
		if r.Belongs(agent, start) {
			t.Errorf("%s run accepted", name)
		}
	}
}

// TestHR612_TheStatementNamesTheTwin: the image, that a twin was tested, and
// a scripted run say so; never compliance (D305, D310).
// Covers: F904
func TestHR612_TheStatementNamesTheTwin(t *testing.T) {
	c := domain.Campaign{ImageDigest: "sha256:" + strings.Repeat("a", 64), Scripted: true}
	s := c.Statement()
	for _, want := range []string{c.ImageDigest, "range twin", "not production", "scripted stand-in", "Not a compliance certification"} {
		if !strings.Contains(s, want) {
			t.Errorf("statement lacks %q: %s", want, s)
		}
	}
	c.Scripted = false
	if s := c.Statement(); strings.Contains(s, "scripted") {
		t.Errorf("a real run says scripted: %s", s)
	}
}
