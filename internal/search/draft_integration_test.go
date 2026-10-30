// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package search

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"

	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeModel is the model: it answers with out through the call's own parser.
// No test reaches a real provider.
type fakeModel struct {
	out  string
	last modelapp.Call
}

func (m *fakeModel) Draft(_ context.Context, call modelapp.Call) (modelapp.Result, error) {
	m.last = call
	id := ids.NewV7()
	if err := call.Parse(id, []byte(m.out)); err != nil {
		return modelapp.Result{}, err
	}
	return modelapp.Result{ID: id}, nil
}

func answer(entity, name string) string {
	return `{"entity":"` + entity + `","builtin":"","environment":"","outcomes":["denied"],"time":"last 7 days",` +
		`"names":[{"phrase":"` + name + `","kind":"agent"}],"ambiguities":[]}`
}

// Covers: F304
func TestHR542_ADraftSendsTheTextAndNamesItMayReadAndNoRecord(t *testing.T) {
	f := newM11Fx(t)
	f.s.Defs = catalog{"payments.refund.create"}
	m := &fakeModel{out: answer("transactions", "alpha")}
	d := &Drafter{Search: f.s, Model: m}
	const text = "denied actions by alpha"
	if _, err := d.DraftQuery(as(f.auditor), text, "UTC"); err != nil {
		t.Fatal(err)
	}
	if m.last.Text != text || m.last.Task != ports.TaskSearchQuery {
		t.Fatalf("call: %+v", m.last)
	}
	if !slices.Contains(m.last.Catalog.Entities, "transactions") || !slices.Equal(m.last.Catalog.OperationGroups, []string{"payments.refund.*"}) {
		t.Fatalf("catalog: %+v", m.last.Catalog)
	}
	sent, err := json.Marshal(m.last.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []string{"alpha", "bravo", "charlie", f.agentA.String(), f.runA.String(), "Exfil"} {
		if strings.Contains(string(sent), record) || strings.Contains(string(m.last.Schema), record) {
			t.Errorf("the request holds the record %s", record)
		}
	}
}

// Covers: F304
func TestHR544_ADraftedQueryIsShownAndNotRun(t *testing.T) {
	f := newM11Fx(t)
	m := &fakeModel{out: answer("transactions", "alpha")}
	d := &Drafter{Search: f.s, Model: m}
	got, err := d.DraftQuery(as(f.auditor), "denied actions by alpha", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	in := got.Interpretation
	if in.NeedsClarification || in.Query == nil || in.Query.Filters.Agent == nil || *in.Query.Filters.Agent != f.agentA {
		t.Fatalf("interpretation: %+v", in)
	}
	if len(in.Query.Filters.Decisions) == 0 || in.Start == nil || got.Call.IsZero() {
		t.Fatalf("draft: %+v", got)
	}
}

// A model naming a record the viewer may not read learns nothing, and the
// viewer sees what a missing record shows.
//
// Covers: F304
func TestT235_HiddenRecordsReadLikeMissingOnes(t *testing.T) {
	f := newM11Fx(t)
	m := &fakeModel{}
	d := &Drafter{Search: f.s, Model: m}
	draft := func(name string) Interpretation {
		t.Helper()
		m.out = answer("transactions", name)
		got, err := d.DraftQuery(as(f.responder), "denied actions by "+name, "UTC")
		if err != nil {
			t.Fatal(err)
		}
		return got.Interpretation
	}
	hidden, missing := draft("bravo"), draft("zulu")
	if hidden.Query != nil || !slices.Equal(hidden.UnknownWords, []string{"bravo"}) || !slices.Equal(missing.UnknownWords, []string{"zulu"}) ||
		len(hidden.Ambiguities) != 0 || len(hidden.Clarifications) != len(missing.Clarifications) {
		t.Fatalf("hidden %+v, missing %+v", hidden, missing)
	}
}
