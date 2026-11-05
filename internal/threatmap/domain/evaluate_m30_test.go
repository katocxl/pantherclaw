// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"strings"
	"testing"

	"buf.build/go/protovalidate"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapping"
)

// TestHR714_NarrowedTriggerIsPartialNeverEvidenced: an ACTIVE automation
// whose trigger also tests something other than the rule reads PARTIAL
// NARROWED_TRIGGER; without the extra test it reads EVIDENCED (G0 M30 D948).
//
// Covers: HR-714
func TestHR714_NarrowedTriggerIsPartialNeverEvidenced(t *testing.T) {
	if r := technique(t, eval(business()), "T0001").Respond; r.State != domain.LaneEvidenced {
		t.Fatalf("plain trigger: %+v", r)
	}
	in := business()
	in.Automations[0].Narrowed = true
	r := technique(t, eval(in), "T0001").Respond
	if r.State != domain.LanePartial || !hasReason(r.Reasons, domain.ReasonNarrowedTrigger) {
		t.Fatalf("narrowed trigger: %s %v", r.State, r.Reasons)
	}
}

// TestHR715_ConnectorRefusalsCountInSeen: an execution outcome code that a
// mapped control names counts as a refusal on its techniques; a code no
// mapped control names does not (G0 M30 D947a, D948).
//
// Covers: HR-715
func TestHR715_ConnectorRefusalsCountInSeen(t *testing.T) {
	m := fixtureMapping()
	m.Controls[0].OutcomeCodes = []string{"table_not_allowed"}
	in := business()
	in.Outcomes = []domain.OutcomeCount{{Code: "table_not_allowed", Count: 4}, {Code: "row_limit", Count: 7}}
	s := technique(t, domain.Evaluate(fixtureCatalog(), m, in), "T0001").Seen
	if s.Refusals != 5+4 {
		t.Fatalf("refusals %d, want 9 (5 decisions + 4 connector refusals)", s.Refusals)
	}
	in.Outcomes = []domain.OutcomeCount{{Code: "row_limit", Count: 7}}
	if s := technique(t, domain.Evaluate(fixtureCatalog(), m, in), "T0001").Seen; s.Refusals != 5 {
		t.Fatalf("an unmapped outcome code counted: %d", s.Refusals)
	}
}

// TestHR715_QueryScopeNamesItsOutcomeCodes: prevent.query_scope names the
// connector refusals table_not_allowed and column_not_allowed (and not
// scope_unsupported, refused before dispatch), and RecordExecutionRequest
// takes only a lower-case code of at most 64 characters (G0 M30 D947a).
//
// Covers: HR-715
func TestHR715_QueryScopeNamesItsOutcomeCodes(t *testing.T) {
	i := slices.IndexFunc(mapping.Prevent, func(c mapping.PreventControl) bool { return c.ID == "prevent.query_scope" })
	if i < 0 {
		t.Fatal("no prevent.query_scope")
	}
	if got := mapping.Prevent[i].OutcomeCodes; !slices.Equal(got, []string{"table_not_allowed", "column_not_allowed"}) {
		t.Fatalf("outcome codes %v", got)
	}
	long := make([]byte, 65)
	for j := range long {
		long[j] = 'a'
	}
	for code, ok := range map[string]bool{
		"":                  true,
		"table_not_allowed": true,
		"Table_not_allowed": false,
		"9table":            false,
		"table-not-allowed": false,
		string(long[:64]):   true,
		string(long):        false,
	} {
		err := protovalidate.Validate(&pb.RecordExecutionRequest{OutcomeCode: code})
		if hasField(err, "outcome_code") == ok {
			t.Errorf("outcome_code %q: %v", code, err)
		}
	}
}

// hasField reports whether err names field (other fields of the request
// may fail too; only this one is under test).
func hasField(err error, field string) bool {
	return err != nil && strings.Contains(err.Error(), field)
}
