// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"errors"
	"slices"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

const goodRule = `{"kind":"FORBID","summary":"Forbid refunds","operations":["payments.*"],"conditions":[],"reason":"NO_REFUNDS",` +
	`"approval":null,"step_up":null,"constraint":null}`

var visibleOps = []string{"payments.refund.create", "tickets.close"}

var testFields = fieldsOf([]Param{
	{Name: "amount", Type: defs.TypeMoney},
	{Name: "count", Type: defs.TypeInteger},
	{Name: "live", Type: defs.TypeBoolean},
	{Name: "reference", Type: defs.TypeIdentifier},
	{Name: "tier", Type: defs.TypeEnum, Values: []string{"gold"}},
})

func policyAnswer(rules string) []byte {
	return []byte(`{"rules":[` + rules + `],"ambiguities":[]}`)
}

// closed fails on any object in s that allows more than it lists.
func closed(t *testing.T, s any) {
	t.Helper()
	switch v := s.(type) {
	case ports.Schema:
		if v["type"] == "object" {
			if v["additionalProperties"] != false {
				t.Errorf("an open object: %v", v)
			}
			if _, tools := v["tools"]; tools {
				t.Error("a schema offers tools")
			}
		}
		for _, sub := range v {
			closed(t, sub)
		}
	case map[string]ports.Schema:
		for _, sub := range v {
			closed(t, sub)
		}
	case []ports.Schema:
		for _, sub := range v {
			closed(t, sub)
		}
	}
}

// Covers: F181
func TestT235_ThePolicySchemaIsClosedAndCannotWeakenARule(t *testing.T) {
	closed(t, policySchema(testFields))
	raw, err := policySchema(testFields).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"exceptable", "emergency", "labels", "facts", "ANNOTATE", "environments"} {
		if strings.Contains(string(raw), field) {
			t.Errorf("the schema offers %s", field)
		}
	}
}

// Covers: F181
func TestHR543_OnlyAStrictlyValidPolicyAnswerIsAccepted(t *testing.T) {
	call := ids.NewV7()
	rules, as, err := parsePolicy("forbid refunds", policyAnswer(goodRule), call, visibleOps, testFields)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || len(as) != 0 || rules[0].Kind != pdomain.Forbid || !strings.HasPrefix(rules[0].ID, "model-") {
		t.Fatalf("parsed: %+v %+v", rules, as)
	}
	refused := map[string]string{
		"not JSON":       `here is your policy`,
		"two documents":  string(policyAnswer(goodRule)) + `{}`,
		"extra field":    `{"rules":[` + goodRule + `],"ambiguities":[],"publish":true}`,
		"extra in rule":  string(policyAnswer(strings.Replace(goodRule, `"kind"`, `"exceptable":true,"kind"`, 1))),
		"emergency":      string(policyAnswer(strings.Replace(goodRule, `"kind"`, `"emergency":true,"kind"`, 1))),
		"no rules":       string(policyAnswer("")),
		"unknown kind":   string(policyAnswer(strings.Replace(goodRule, "FORBID", "ALLOW", 1))),
		"annotate":       string(policyAnswer(strings.Replace(goodRule, "FORBID", "ANNOTATE", 1))),
		"unreadable op":  string(policyAnswer(strings.Replace(goodRule, "payments.*", "secrets.*", 1))),
		"unreadable op2": string(policyAnswer(strings.Replace(goodRule, "payments.*", "payments.refund.delete", 1))),
		"bad reason":     string(policyAnswer(strings.Replace(goodRule, "NO_REFUNDS", "no refunds", 1))),
		"missing fields": string(policyAnswer(`{"kind":"REQUIRE_APPROVAL","summary":"x","operations":["tickets.close"],"conditions":[],"reason":"NEEDS_OK"}`)),
		"wrong type":     `{"rules":"everything","ambiguities":[]}`,
	}
	for name, output := range refused {
		if _, _, err := parsePolicy("forbid refunds", []byte(output), call, visibleOps, testFields); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Covers: F181
func TestHR543_AConstraintLimitIsCheckedAgainstItsParamsType(t *testing.T) {
	answer := func(constraint string) []byte {
		rule := strings.Replace(goodRule, `"constraint":null`, `"constraint":`+constraint, 1)
		return policyAnswer(strings.Replace(rule, "FORBID", string(pdomain.Constrain), 1))
	}
	accepted := []string{
		`{"kind":"amount_max","param":"amount","max":"100.00","currency":"USD","values":[]}`,
		`{"kind":"count_max","param":"count","max":"5","currency":"","values":[]}`,
		`{"kind":"allowed_values","param":"tier","max":"","currency":"","values":["gold"]}`,
	}
	for _, c := range accepted {
		if _, _, err := parsePolicy("limit refunds", answer(c), ids.NewV7(), visibleOps, testFields); err != nil {
			t.Errorf("%s: %v", c, err)
		}
	}
	refused := map[string]string{
		"not a number":     `{"kind":"amount_max","param":"amount","max":"a lot","currency":"USD","values":[]}`,
		"no currency":      `{"kind":"amount_max","param":"amount","max":"100.00","currency":"","values":[]}`,
		"not a currency":   `{"kind":"amount_max","param":"amount","max":"100.00","currency":"true || true","values":[]}`,
		"not a whole one":  `{"kind":"count_max","param":"count","max":"1.5","currency":"","values":[]}`,
		"no order":         `{"kind":"count_max","param":"reference","max":"5","currency":"","values":[]}`,
		"unoffered param":  `{"kind":"count_max","param":"none","max":"5","currency":"","values":[]}`,
		"a stray currency": `{"kind":"allowed_values","param":"tier","max":"","currency":"USD","values":["gold"]}`,
	}
	for name, c := range refused {
		if _, _, err := parsePolicy("limit refunds", answer(c), ids.NewV7(), visibleOps, testFields); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Covers: F181, F304
func TestHR543_VagueTermsAreSettledOrTheDraftIsRefused(t *testing.T) {
	const text = "hold refunds for a lot of money"
	if err := CheckAmbiguities(text, nil); !errors.Is(err, ports.ErrInvalidOutput) {
		t.Fatalf("settled silently: %v", err)
	}
	if err := CheckAmbiguities(text, []Ambiguity{{Term: "a lot of money", ProposedThreshold: "over 1000 USD"}}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Ambiguity{
		"no threshold":    {Term: "a lot of money"},
		"not in the text": {Term: "many dollars", ProposedThreshold: "x"},
		"control":         {Term: "a lot of money", ProposedThreshold: "1\n2"},
		"too long":        {Term: "a lot of money", ProposedThreshold: strings.Repeat("x", maxAmbiguity+1)},
	}
	for name, a := range bad {
		if err := CheckAmbiguities(text, []Ambiguity{a}); !errors.Is(err, ports.ErrInvalidOutput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckAmbiguities("forbid refunds", nil); err != nil {
		t.Fatalf("nothing vague: %v", err)
	}
}

// Covers: F181, F304
func TestHR542_TheCatalogHoldsOnlyOperationNames(t *testing.T) {
	got := OperationGroups([]string{"payments.refund.create", "payments.refund.void", "tickets.close", "tickets.close"})
	if want := []string{"payments.refund.*", "tickets.close"}; !slices.Equal(got, want) {
		t.Fatalf("groups = %v", got)
	}
	many := make([]string, 0, maxGroups+10)
	for i := range maxGroups + 10 {
		many = append(many, "a"+strings.Repeat("b", i%50)+"."+string(rune('a'+i%26))+strings.Repeat("c", i%40))
	}
	if n := len(OperationGroups(many)); n > maxGroups {
		t.Fatalf("groups are unbounded: %d", n)
	}
}

// Covers: F181
func TestT234_AnEstimateCoversAWholeAnswerAndTheInput(t *testing.T) {
	small := Call{Text: "x"}.estimate()
	if small <= ports.MaxOutputTokens {
		t.Fatalf("estimate = %d", small)
	}
	big := Call{Text: strings.Repeat("x", 3000), Catalog: ports.Catalog{OperationGroups: []string{strings.Repeat("y", 3000)}}}
	if big.estimate() != small+2000 {
		t.Fatalf("estimate = %d, small = %d", big.estimate(), small)
	}
}
