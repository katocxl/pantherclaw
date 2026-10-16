// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// names is a fake resolver: the records each lowercased phrase names
// exactly, among the kinds asked.
type names map[string][]Match

func (n names) resolve(_ context.Context, phrase string, kinds []FindKind) ([]Match, error) {
	var out []Match
	for _, m := range n[phrase] {
		if slices.Contains(kinds, m.Kind) {
			out = append(out, m)
		}
	}
	return out, nil
}

func named(k FindKind, label string) Match {
	id := ids.NewV7().String()
	ev := strings.TrimSuffix(string(k), "s")
	if k == FindPeople {
		ev = "user"
	}
	return Match{Kind: k, ID: id, Label: label, MatchedBy: MatchedNameExact, Evidence: []string{ev + ":" + id}}
}

var askNow = time.Date(2026, 10, 15, 15, 30, 0, 0, time.UTC) // a Thursday

func ask(t *testing.T, n names, q, tz string) Interpretation {
	t.Helper()
	in, err := interpret(context.Background(), q, tz, askNow, n.resolve)
	if err != nil {
		t.Fatalf("%q: %v", q, err)
	}
	return in
}

// TestHR295_QuestionsReadAsQueries (F305, F5): the fixed lexicon reads
// entities, outcomes, environments, time phrases in the asker's time zone,
// names the viewer may read, and the built-in phrasings; the interpretation
// says what it understood and what the rows mean.
func TestHR295_QuestionsReadAsQueries(t *testing.T) {
	deploy := named(FindAgents, "deploy")
	stripe := named(FindConnections, "stripe")
	alice := named(FindPeople, "alice")
	n := names{"deploy": {deploy}, "stripe": {stripe}, "alice": {alice}}

	in := ask(t, n, "Which actions were denied in production yesterday?", "Europe/London")
	q := in.Query
	if in.NeedsClarification || q == nil || q.Entity != EntityTransactions || in.Meaning != MeaningDecisions ||
		!slices.Equal(q.Filters.Decisions, []string{"DENY", "CANNOT_AUTHORIZE"}) ||
		!slices.Equal(q.Filters.EnvKinds, []string{"PRODUCTION"}) || in.Environment != "PRODUCTION" {
		t.Fatalf("denied in production yesterday: %+v", in)
	}
	// Yesterday in London (BST, UTC+1) runs from 23:00 UTC to 23:00 UTC.
	if !q.Filters.Start.Equal(time.Date(2026, 10, 13, 23, 0, 0, 0, time.UTC)) ||
		!q.Filters.End.Equal(time.Date(2026, 10, 14, 23, 0, 0, 0, time.UTC)) || in.Timezone != "Europe/London" {
		t.Fatalf("range %v–%v in %s", q.Filters.Start, q.Filters.End, in.Timezone)
	}
	if len(in.Matched) < 4 || len(in.UnknownWords) != 0 {
		t.Fatalf("matched %v, unknown %v", in.Matched, in.UnknownWords)
	}

	in = ask(t, n, "failed actions by agent deploy last 3 days", "")
	if q := in.Query; q == nil || q.Filters.Agent == nil || q.Filters.Agent.String() != deploy.ID ||
		!slices.Equal(q.Filters.EffectStates, []string{"NONE_CONFIRMED", "PARTIAL"}) || in.Meaning != MeaningEffects ||
		!q.Filters.Start.Equal(askNow.Add(-72*time.Hour)) || q.Filters.End != nil {
		t.Fatalf("failed by deploy: %+v", in)
	}

	in = ask(t, n, "agents that used stripe this week", "UTC")
	if q := in.Query; q == nil || q.Entity != EntityAgents || q.Filters.UsedConnection == nil ||
		!q.Filters.Start.Equal(time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("agents using stripe: %+v", in)
	}

	in = ask(t, n, `open alerts since 2026-10-01`, "")
	if in.Query != nil || !slices.Contains(in.UnknownWords, "open") {
		t.Fatalf("an unknown word ran: %+v", in)
	}
	in = ask(t, n, `alerts since 2026-10-01`, "")
	if q := in.Query; q == nil || q.Entity != EntityAlerts || !q.Filters.Start.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("alerts since: %+v", in)
	}

	for question, want := range map[string]Builtin{
		"unused grants":                                       BuiltinUnusedGrants,
		"recent authority changes for deploy":                 BuiltinRecentAuthorityChange,
		"payment-capable tools":                               BuiltinToolCapability,
		"actions for alice":                                   BuiltinActionsForPrincipal,
		"what depends on stripe":                              BuiltinConnectionDependents,
		"widest exposure":                                     BuiltinWidestExposure,
		"production access between 2026-10-01 and 2026-10-07": BuiltinProductionAccess,
		"who can write to prod-db":                            BuiltinWhoCanWrite,
	} {
		in := ask(t, n, question, "")
		if in.Builtin == nil || in.Builtin.Name != want || in.NeedsClarification {
			t.Errorf("%q: %+v", question, in)
		}
	}
	if in := ask(t, n, "who can write to prod-db", ""); in.Builtin.Params.Resource != "prod-db" {
		t.Errorf("who can write: %+v", in.Builtin.Params)
	}
	if in := ask(t, n, "actions for alice", ""); in.Builtin.Params.PrincipalUser == nil {
		t.Errorf("actions for alice: %+v", in.Builtin.Params)
	}
	txn := named(FindTransactions, "payments.refund.create")
	n[txn.ID] = []Match{{Kind: FindTransactions, ID: txn.ID, Label: txn.Label, MatchedBy: MatchedID, Evidence: []string{"transaction:" + txn.ID}}}
	if in := ask(t, n, "why was "+txn.ID+" allowed?", ""); in.Builtin == nil || in.Builtin.Name != BuiltinWhyAllowed ||
		in.Builtin.Params.Transaction == nil || in.Builtin.Params.Transaction.String() != txn.ID {
		t.Errorf("why allowed: %+v", in)
	}
}

// TestHR295_ParserNeverGuesses (F5): an unknown word, a name the viewer
// may not read, two records with one name, two kinds of record or two
// ranges all stop the question with a clarification; nothing runs.
func TestHR295_ParserNeverGuesses(t *testing.T) {
	n := names{"deploy": {named(FindAgents, "deploy"), named(FindAgents, "deploy")}}
	for q, check := range map[string]func(Interpretation) bool{
		"denied actions by deploy": func(in Interpretation) bool {
			return len(in.Ambiguities) == 1 && in.Ambiguities[0].Phrase == "deploy" && len(in.Ambiguities[0].Candidates) == 2
		},
		"denied actions by zulu":              func(in Interpretation) bool { return slices.Equal(in.UnknownWords, []string{"zulu"}) },
		"denied actions frobnicated":          func(in Interpretation) bool { return slices.Equal(in.UnknownWords, []string{"frobnicated"}) },
		"denied grants":                       func(in Interpretation) bool { return len(in.Clarifications) == 1 },
		"alerts and cases":                    func(in Interpretation) bool { return len(in.Clarifications) >= 1 },
		"actions today yesterday":             func(in Interpretation) bool { return len(in.Clarifications) >= 1 },
		"production":                          func(in Interpretation) bool { return len(in.Clarifications) >= 1 },
		`actions by "night shift"`:            func(in Interpretation) bool { return slices.Contains(in.UnknownWords, "night shift") },
		"widest exposure in production":       func(in Interpretation) bool { return len(in.Clarifications) >= 1 },
		"who can write to prod-db and others": func(in Interpretation) bool { return len(in.UnknownWords) >= 1 },
	} {
		in := ask(t, n, q, "")
		if !in.NeedsClarification || in.Query != nil || in.Builtin != nil || !check(in) {
			t.Errorf("%q: %+v", q, in)
		}
	}
	for _, bad := range []struct{ q, tz string }{
		{"", ""},
		{strings.Repeat("a ", 151), ""},
		{"actions\x00", ""},
		{"actions", "Mars/Olympus"},
		{"actions", "Local"},
		{`actions by "deploy`, ""},
		{"actions since 2026-02-30", ""},
		{"actions between 2026-10-07 and 2026-10-01", ""},
		{"actions since 2020-01-01", ""},
	} {
		if _, err := interpret(context.Background(), bad.q, bad.tz, askNow, n.resolve); !invalid(err) {
			t.Errorf("%q in %q: accepted (%v)", bad.q, bad.tz, err)
		}
	}
}

// TestT130_HiddenNamesReadLikeMissingOnes: the resolver answers under the
// viewer's permissions, so a record the viewer may not read is an unknown
// word exactly like a name nobody has.
func TestT130_HiddenNamesReadLikeMissingOnes(t *testing.T) {
	visible := names{}
	hidden := ask(t, visible, "denied actions by bravo", "")
	missing := ask(t, visible, "denied actions by zulu", "")
	if !slices.Equal(hidden.UnknownWords, []string{"bravo"}) || !slices.Equal(missing.UnknownWords, []string{"zulu"}) ||
		len(hidden.Clarifications) != len(missing.Clarifications) || hidden.Query != nil {
		t.Fatalf("hidden %+v vs missing %+v", hidden, missing)
	}
}

// TestT130_FindTextNeverBecomesAPattern: what a person types is matched
// literally: LIKE's wildcards and escape are escaped, and an id prefix is
// a key range, never text.
func TestT130_FindTextNeverBecomesAPattern(t *testing.T) {
	if got := likeContains(`50%_off\`); got != `%50\%\_off\\%` {
		t.Fatalf("likeContains: %q", got)
	}
	lo, hi, exact := idRange("0190ABCD-12")
	if lo == nil || exact || lo.String() != "0190abcd-1200-0000-0000-000000000000" || hi.String() != "0190abcd-12ff-ffff-ffff-ffffffffffff" {
		t.Fatalf("prefix range %v %v", lo, hi)
	}
	id := ids.NewV7()
	if lo, hi, exact := idRange(id.String()); !exact || *lo != id || *hi != id {
		t.Fatal("exact id")
	}
	for _, s := range []string{"0190abc", "0190abcz12", "deploy-bot", strings.Repeat("a", 33)} {
		if lo, _, _ := idRange(s); lo != nil {
			t.Errorf("%q read as an id", s)
		}
	}
	for _, r := range []FindRequest{
		{Text: "a"},
		{Text: strings.Repeat("a", 101)},
		{Text: "ab\x01"},
		{Text: "ab", Limit: 11},
		{Text: "ab", Kinds: []FindKind{"secrets"}},
	} {
		if _, err := r.validate(); !invalid(err) {
			t.Errorf("%+v accepted", r)
		}
	}
}

// TestT130_CSVCellsNeverRunAsFormulas: exported cells a spreadsheet would
// evaluate are prefixed.
func TestT130_CSVCellsNeverRunAsFormulas(t *testing.T) {
	b, _, err := encode([]Item{{
		Entity: EntityAgents, ID: "x", Label: "=HYPERLINK(\"http://evil\")",
		Fields: map[string]string{"name": "+1", "team": "ok"},
	}}, FormatCSV)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `'=HYPERLINK`) || !strings.Contains(s, "'+1") || !strings.HasPrefix(s, "entity,id,time,label,name,team,evidence") {
		t.Fatalf("csv: %s", s)
	}
}

// TestT130_CorrelationParameters: incident_correlation takes one of an
// incident or a case and at most 30 days, nothing else.
func TestT130_CorrelationParameters(t *testing.T) {
	id := ids.NewV7()
	ok := BuiltinQuery{Name: BuiltinIncidentCorrelation, Params: Params{Incident: &id, Days: 30}}
	if err := ok.validateCorrelation(); err != nil {
		t.Fatal(err)
	}
	if err := (Spec{Builtin: &ok}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Params{{}, {Incident: &id, Case: &id}, {Case: &id, Days: 31}, {Case: &id, Agent: &id}} {
		if err := (BuiltinQuery{Name: BuiltinIncidentCorrelation, Params: p}).validateCorrelation(); !invalid(err) {
			t.Errorf("%+v accepted", p)
		}
	}
	if got := ngrams([]string{"a", "b", "c", "d"}); !slices.Equal(got, []string{"a\x00b\x00c", "b\x00c\x00d"}) {
		t.Errorf("ngrams %q", got)
	}
}
