// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

const goodRule = `{"kind":"FORBID","summary":"Forbid refunds","operations":["payments.*"],"when":"true","reason":"NO_REFUNDS",` +
	`"approval":null,"step_up":null,"constraint":null}`

var visibleOps = []string{"payments.refund.create", "tickets.close"}

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
	closed(t, policySchema())
	raw, err := policySchema().Encode()
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
	rules, as, err := parsePolicy("forbid refunds", policyAnswer(goodRule), call, visibleOps)
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
		"missing fields": string(policyAnswer(`{"kind":"REQUIRE_APPROVAL","summary":"x","operations":["tickets.close"],"when":"true","reason":"NEEDS_OK"}`)),
		"wrong type":     `{"rules":"everything","ambiguities":[]}`,
	}
	for name, output := range refused {
		if _, _, err := parsePolicy("forbid refunds", []byte(output), call, visibleOps); !errors.Is(err, ports.ErrInvalidOutput) {
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
	if err := CheckAmbiguities(text, []Ambiguity{{Phrase: "a lot of money", ProposedThreshold: "over 1000 USD"}}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Ambiguity{
		"no threshold":    {Phrase: "a lot of money"},
		"not in the text": {Phrase: "many dollars", ProposedThreshold: "x"},
		"control":         {Phrase: "a lot of money", ProposedThreshold: "1\n2"},
		"too long":        {Phrase: "a lot of money", ProposedThreshold: strings.Repeat("x", maxAmbiguity+1)},
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
