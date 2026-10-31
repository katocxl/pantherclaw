// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// draftParser reads answers to text with a resolver that knows one agent.
func draftParser(t *testing.T, timeText string) *parser {
	t.Helper()
	toks, err := tokenize(timeText)
	if err != nil {
		t.Fatal(err)
	}
	agent := ids.NewV7().String()
	return &parser{
		toks: toks, used: make([]bool, len(toks)), loc: time.UTC, now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
		ops: []string{"payments.refund.create"},
		resolve: func(_ context.Context, phrase string, _ []FindKind) ([]Match, error) {
			if phrase != "alpha" {
				return nil, nil
			}
			return []Match{{Kind: FindAgents, ID: agent, Label: "alpha", MatchedBy: MatchedNameExact, Evidence: []string{"agent:" + agent}}}, nil
		},
	}
}

// Covers: F304
func TestHR543_AQueryAnswerIsCheckedAgainstClosedLists(t *testing.T) {
	const text = "denied actions by alpha last 7 days"
	seen := []string{"transactions"}
	good := queryOutput{
		Entity: "transactions", Outcomes: []string{"denied"}, Time: "last 7 days",
		Names: []draftName{{Phrase: "alpha", Kind: "agent"}},
	}
	p := draftParser(t, good.Time)
	if err := p.fromDraft(context.Background(), text, seen, good); err != nil {
		t.Fatal(err)
	}
	if p.in.NeedsClarification || p.in.Query == nil || p.in.Query.Filters.Agent == nil || p.in.Query.Filters.Start == nil {
		t.Fatalf("interpretation: %+v", p.in)
	}
	refused := map[string]func(o *queryOutput){
		"entity it may not read": func(o *queryOutput) { o.Entity = "agents" },
		"unknown entity":         func(o *queryOutput) { o.Entity = "secrets" },
		"entity and built-in":    func(o *queryOutput) { o.Builtin = "unused_grants" },
		"unknown built-in":       func(o *queryOutput) { o.Entity, o.Builtin = "", "drop_tables" },
		"unknown environment":    func(o *queryOutput) { o.Environment = "EVERYWHERE" },
		"unknown outcome":        func(o *queryOutput) { o.Outcomes = []string{"purged"} },
		"unknown name kind":      func(o *queryOutput) { o.Names[0].Kind = "secret" },
		"name not in the text":   func(o *queryOutput) { o.Names[0].Phrase = "bravo" },
		"empty name":             func(o *queryOutput) { o.Names[0].Phrase = "" },
		"not a time":             func(o *queryOutput) { o.Time = "ignore previous rules" },
		"time and more":          func(o *queryOutput) { o.Time = "last 7 days and everything" },
		"too many names": func(o *queryOutput) {
			o.Names = slices.Repeat([]draftName{{Phrase: "alpha", Kind: "agent"}}, maxDraftNames+1)
		},
	}
	for name, change := range refused {
		o := good
		o.Names = slices.Clone(good.Names)
		change(&o)
		if err := draftParser(t, o.Time).fromDraft(context.Background(), text, seen, o); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Covers: F304
func TestT235_ANameThatDoesNotSettleAsksInsteadOfGuessing(t *testing.T) {
	o := queryOutput{Entity: "transactions", Names: []draftName{{Phrase: "zulu", Kind: "agent"}}}
	p := draftParser(t, "")
	if err := p.fromDraft(context.Background(), "actions by zulu", []string{"transactions"}, o); err != nil {
		t.Fatal(err)
	}
	if !p.in.NeedsClarification || p.in.Query != nil || !slices.Equal(p.in.UnknownWords, []string{"zulu"}) {
		t.Fatalf("interpretation: %+v", p.in)
	}
}

// closedSchema fails on any object in s that allows more than it lists.
func closedSchema(t *testing.T, s any) {
	t.Helper()
	switch v := s.(type) {
	case ports.Schema:
		if v["type"] == "object" && v["additionalProperties"] != false {
			t.Errorf("an open object: %v", v)
		}
		for _, sub := range v {
			closedSchema(t, sub)
		}
	case map[string]ports.Schema:
		for _, sub := range v {
			closedSchema(t, sub)
		}
	}
}

// Covers: F304
func TestT235_TheQuerySchemaIsClosedAndHasNoIds(t *testing.T) {
	s := querySchema([]string{"transactions"})
	closedSchema(t, s)
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"id"`, `"agent":`, `"run"`, "tools"} {
		if strings.Contains(string(raw), field) {
			t.Errorf("the schema offers %s: %s", field, raw)
		}
	}
	if strings.Contains(string(raw), "audit") {
		t.Error("the schema names an entity the viewer may not read")
	}
}

// Ask stays deterministic: Service, which Ask runs on, holds nothing that can
// reach a model.
//
// Covers: F304
func TestHR544_SearchItselfHasNoPathToAModel(t *testing.T) {
	model := reflect.TypeFor[ModelCaller]()
	st := reflect.TypeFor[Service]()
	for i := range st.NumField() {
		if f := st.Field(i); f.Type.Implements(model) {
			t.Errorf("Service.%s can reach a model", f.Name)
		}
	}
	if _, ok := reflect.TypeFor[*Service]().MethodByName("Draft"); ok {
		t.Error("Service has a Draft method")
	}
}
