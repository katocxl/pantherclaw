// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func invalid(err error) bool {
	var e *pcerr.Error
	return errors.As(err, &e) && e.Code() == pcerr.InvalidArgument
}

// TestQueryValidate: each entity takes only its own typed filters, and
// values are bounded and well formed; there is no free text.
func TestQueryValidate(t *testing.T) {
	id := ids.NewV7()
	now := time.Now()
	earlier := now.Add(-time.Hour)
	long := make([]string, maxListValues+1)
	for i := range long {
		long[i] = "ALLOW"
	}
	for _, tc := range []struct {
		name string
		q    Query
		ok   bool
	}{
		{"transactions", Query{Entity: EntityTransactions, Filters: Filters{Agent: &id, Decisions: []string{"DENY"}, Start: &earlier, End: &now}}, true},
		{"unknown entity", Query{Entity: "secrets"}, false},
		{"filter of another entity", Query{Entity: EntityConnections, Filters: Filters{Agent: &id}}, false},
		{"audit kind outside audit", Query{Entity: EntityAudit, Filters: Filters{KindPrefix: "receipt."}}, false},
		{"audit kind", Query{Entity: EntityAudit, Filters: Filters{KindPrefix: "audit.grant."}}, true},
		{"sql in operation", Query{Entity: EntityTransactions, Filters: Filters{Operation: "x'; DROP TABLE pc.orgs; --"}}, false},
		{"operation and prefix", Query{Entity: EntityTransactions, Filters: Filters{Operation: "a.b", OperationPrefix: "a."}}, false},
		{"both principals", Query{Entity: EntityRuns, Filters: Filters{PrincipalUser: &id, PrincipalSA: &id}}, false},
		{"too many values", Query{Entity: EntityTransactions, Filters: Filters{Decisions: long}}, false},
		{"malformed value", Query{Entity: EntityRuns, Filters: Filters{States: []string{"ACTIVE OR 1=1"}}}, false},
		{"backwards range", Query{Entity: EntityRuns, Filters: Filters{Start: &now, End: &earlier}}, false},
	} {
		err := tc.q.Validate()
		if tc.ok && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if !tc.ok && !invalid(err) {
			t.Errorf("%s: accepted (%v)", tc.name, err)
		}
	}
	for _, e := range entities {
		if _, ok := runners[e]; !ok {
			t.Errorf("%s has no runner", e)
		}
		if _, ok := entityPerm[e]; !ok {
			t.Errorf("%s has no read permission", e)
		}
	}
}

// TestBuiltinsExpand: every built-in query expands to a valid structured
// query, refuses parameters it does not take, and carries its notes.
func TestBuiltinsExpand(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	id := ids.NewV7()
	params := map[Builtin]Params{
		BuiltinProductionAccess:      {},
		BuiltinWhyAllowed:            {Transaction: &id},
		BuiltinToolCapability:        {Effect: "funds."},
		BuiltinUnusedGrants:          {Days: 10},
		BuiltinActionsForPrincipal:   {PrincipalUser: &id},
		BuiltinConnectionDependents:  {Connection: &id},
		BuiltinDenials:               {TargetType: "charge"},
		BuiltinRecentAuthorityChange: {},
	}
	for _, info := range Builtins() {
		if exposureBuiltin(info.Name) {
			continue // TestExposureBuiltins
		}
		if info.Name == BuiltinIncidentCorrelation {
			continue // TestT130_CorrelationParameters
		}
		p, ok := params[info.Name]
		if !ok {
			t.Fatalf("%s: no test parameters", info.Name)
		}
		q, _, err := BuiltinQuery{Name: info.Name, Params: p}.expand(now)
		if err != nil {
			t.Errorf("%s: %v", info.Name, err)
			continue
		}
		if err := q.Validate(); err != nil {
			t.Errorf("%s: expands to an invalid query: %v", info.Name, err)
		}
	}
	for _, tc := range []BuiltinQuery{
		{Name: "drop_tables"},
		{Name: BuiltinWhyAllowed},
		{Name: BuiltinToolCapability},
		{Name: BuiltinUnusedGrants, Params: Params{Days: 400}},
		{Name: BuiltinActionsForPrincipal},
		{Name: BuiltinActionsForPrincipal, Params: Params{PrincipalUser: &id, PrincipalSA: &id}},
		{Name: BuiltinConnectionDependents},
		{Name: BuiltinDenials, Params: Params{Transaction: &id}},
	} {
		if _, _, err := tc.expand(now); !invalid(err) {
			t.Errorf("%s %+v: accepted (%v)", tc.Name, tc.Params, err)
		}
	}
	q, notes, _ := BuiltinQuery{Name: BuiltinUnusedGrants}.expand(now)
	if q.Filters.UnusedSince == nil || !q.Filters.UnusedSince.Equal(now.Add(-30*24*time.Hour)) || len(notes) != 1 {
		t.Errorf("unused grants default: %+v %v", q.Filters, notes)
	}
	q, _, _ = BuiltinQuery{Name: BuiltinRecentAuthorityChange}.expand(now)
	if q.Filters.Start == nil || !q.Filters.Start.Equal(now.Add(-7*24*time.Hour)) {
		t.Errorf("authority changes default window: %+v", q.Filters)
	}
	_, notes, _ = BuiltinQuery{Name: BuiltinConnectionDependents, Params: Params{Connection: &id}}.expand(now)
	if len(notes) != 1 || notes[0].Code != omissionUnknownDependents {
		t.Errorf("connection dependents must name unknown dependencies: %v", notes)
	}
}

// TestLabels: shadow predictions stay apart from enforced decisions,
// attempts from confirmed effects, material grant changes from narrowing.
func TestLabels(t *testing.T) {
	confirmed, partial := "CONFIRMED", "PARTIAL"
	for _, tc := range []struct {
		mode, decision string
		effect         *string
		want           string
	}{
		{"monitor", "DENY", nil, "SHADOW"},
		{"monitor", "ALLOW", &confirmed, "SHADOW"},
		{"enforce", "DENY", nil, "ENFORCED"},
		{"enforce", "ALLOW", nil, "ATTEMPT"},
		{"enforce", "ALLOW", &partial, "ATTEMPT"},
		{"enforce", "ALLOW", &confirmed, "CONFIRMED"},
	} {
		if got := transactionLabel(tc.mode, tc.decision, tc.effect); got != tc.want {
			t.Errorf("%s %s: %s, want %s", tc.mode, tc.decision, got, tc.want)
		}
	}
	if grantChangeLabel(1, false) != "NEW_GRANT" || grantChangeLabel(3, true) != "MATERIAL" || grantChangeLabel(2, false) != "NARROWING_OR_METADATA" {
		t.Error("grant change labels")
	}
}

// TestCapability: tool-capability search keeps verified, declared and
// unclassified operations apart, and an unclassified one matches any
// effect (it may have any).
func TestCapability(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	pay := &defs.Definition{
		Operation: "payments.refund", Effects: []defs.Effect{{Kind: "funds.transfer"}},
		Assurance: defs.Assurance{Basis: defs.BasisObserved, ValidUntil: "2027-01-01"},
	}
	stale := &defs.Definition{
		Operation: "payments.old", Effects: []defs.Effect{{Kind: "funds.transfer"}},
		Assurance: defs.Assurance{Basis: defs.BasisObserved, ValidUntil: "2026-01-01"},
	}
	declared := &defs.Definition{
		Operation: "payments.charge", SideEffects: []defs.Effect{{Kind: "funds.hold"}},
		Assurance: defs.Assurance{Basis: defs.BasisDeclared, ValidUntil: "2027-01-01"},
	}
	read := &defs.Definition{Operation: "repo.read", Effects: []defs.Effect{{Kind: "none"}}}
	unknown := &defs.Definition{Operation: "tool.mystery"}
	if capability(pay, now) != "VERIFIED" || capability(stale, now) != "DECLARED" ||
		capability(declared, now) != "DECLARED" || capability(unknown, now) != "UNCLASSIFIED" {
		t.Error("capability labels")
	}
	f := Filters{EffectPrefix: "funds."}
	for d, want := range map[*defs.Definition]bool{pay: true, declared: true, read: false, unknown: true} {
		if operationMatches(d, f) != want {
			t.Errorf("%s matches funds.: want %v", d.Operation, want)
		}
	}
}

// TestRangeOf: a range reaching the present is changing; a past one is
// stable (F317).
func TestRangeOf(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	recent := now.Add(-time.Minute)
	if !rangeOf(Filters{}, now).Changing || !rangeOf(Filters{End: &recent}, now).Changing || rangeOf(Filters{End: &old}, now).Changing {
		t.Error("range changing flags")
	}
}

// TestSpecValidate: a saved query holds exactly one valid query, and its
// stored form round-trips.
func TestSpecValidate(t *testing.T) {
	id := ids.NewV7()
	good := []Spec{
		{Query: &Query{Entity: EntityRuns, Filters: Filters{Agent: &id}}},
		{Builtin: &BuiltinQuery{Name: BuiltinDenials}},
	}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Errorf("%+v: %v", s, err)
		}
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var back Spec
		if err := json.Unmarshal(b, &back); err != nil || back.Validate() != nil {
			t.Errorf("round trip %s: %v", b, err)
		}
	}
	for _, s := range []Spec{
		{},
		{Query: &Query{Entity: EntityRuns}, Builtin: &BuiltinQuery{Name: BuiltinDenials}},
		{Query: &Query{Entity: "x"}},
		{Builtin: &BuiltinQuery{Name: "x"}},
	} {
		if err := s.Validate(); !invalid(err) {
			t.Errorf("%+v accepted", s)
		}
	}
	in := SaveInput{Name: "x", Visibility: Team, Spec: good[0]}
	if err := in.validate(); !invalid(err) {
		t.Error("TEAM without a team accepted")
	}
	in = SaveInput{Name: "x", Visibility: Org, Team: &id, Spec: good[0]}
	if err := in.validate(); !invalid(err) {
		t.Error("ORG with a team accepted")
	}
}

// TestScopeIntersect (D69 L3): a filter that reads recorded actions keeps
// only the agents the viewer may read with both permissions.
func TestScopeIntersect(t *testing.T) {
	a, b, c := ids.NewV7(), ids.NewV7(), ids.NewV7()
	all := Scope{Permission: "agent.read", All: true}
	some := Scope{Permission: "agent.read", Agents: []ids.UUID{a, b}}
	ev := Scope{Permission: "evidence.read", Agents: []ids.UUID{b, c}}
	none := Scope{Permission: "evidence.read", Restricted: true}
	if got := some.intersect(ev); got.All || got.Restricted || len(got.Agents) != 1 || got.Agents[0] != b {
		t.Errorf("some ∩ ev: %+v", got)
	}
	if got := all.intersect(ev); got.All || len(got.Agents) != 2 || got.Permission != "agent.read" {
		t.Errorf("all ∩ ev: %+v", got)
	}
	if got := some.intersect(Scope{All: true}); len(got.Agents) != 2 {
		t.Errorf("some ∩ all: %+v", got)
	}
	if got := all.intersect(none); !got.Restricted {
		t.Errorf("all ∩ restricted: %+v", got)
	}
}
