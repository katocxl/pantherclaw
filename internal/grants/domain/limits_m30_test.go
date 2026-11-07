// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// readAction is a read the access rules count (G0 M30 D930).
func readAction() Action {
	a := refund("1", "USD", "duplicate", mondayNoon)
	a.Operation, a.Access, a.Params = "payments.refund.get", defs.AccessRead, nil
	return a
}

// TestHR706_AccessRuleCountsOnlyItsAccess: a count rule with access "read"
// debits reads and skips writes; "*" stands for every operation of that
// access (G0 M30 D930, D930a).
//
// Covers: HR-706
func TestHR706_AccessRuleCountsOnlyItsAccess(t *testing.T) {
	root := rootGrant(t, refundBounds)
	root.Limits = mustLimits(t, `{"budgets": [{"id": "reads", "grouping": "task", "operations": ["*"], "access": "read", "max_count": "2", "period": "day"}]}`)
	if err := root.Limits.validate(true); err != nil {
		t.Fatalf("access rule refused: %v", err)
	}
	dc := DebitContext{Now: mondayNoon, RunID: ids.NewV7(), Principal: alice}
	plan, f := (Chain{Grants: []Grant{root}}).Debits(readAction(), dc)
	if f != nil || len(plan.Budgets) != 1 || plan.Budgets[0].MaxCount == nil || *plan.Budgets[0].MaxCount != 2 {
		t.Fatalf("a read was not counted: %+v %+v", plan, f)
	}
	plan, f = (Chain{Grants: []Grant{root}}).Debits(refund("1", "USD", "duplicate", mondayNoon), dc)
	if f != nil || len(plan.Budgets) != 0 {
		t.Fatalf("a read rule counted a write: %+v %+v", plan, f)
	}
}

// TestHR706_AccessRuleShapeRefused: an access rule needs max_count and
// takes no limit, currency or max_tokens; "*" needs access and stands
// alone; an unknown access is refused (G0 M30 D930, D930a).
//
// Covers: HR-706
func TestHR706_AccessRuleShapeRefused(t *testing.T) {
	bad := map[string]struct{ doc, code string }{
		"no max_count":   {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "access": "read", "currency": "USD", "limit": "5", "period": "day"}]}`, CodeBudgetAccessNeedsCount},
		"with a limit":   {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "access": "read", "max_count": "5", "currency": "USD", "limit": "5", "period": "day"}]}`, CodeBudgetAccessNeedsCount},
		"with tokens":    {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "access": "write", "max_count": "5", "max_tokens": "5", "period": "day"}]}`, CodeBudgetAccessNeedsCount},
		"bare wildcard":  {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["*"], "max_count": "5", "period": "day"}]}`, CodeBudgetWildcardNeedsAccess},
		"mixed wildcard": {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["*", "a.b"], "access": "read", "max_count": "5", "period": "day"}]}`, CodeBudgetWildcardNeedsAccess},
		"unknown access": {`{"budgets": [{"id": "a", "grouping": "task", "operations": ["a.b"], "access": "admin", "max_count": "5", "period": "day"}]}`, ""},
	}
	for name, tt := range bad {
		l, err := DecodeLimits([]byte(tt.doc))
		if err == nil {
			err = l.validate(true)
		}
		if !errors.Is(err, ErrInvalid) || (tt.code != "" && !strings.Contains(err.Error(), tt.code)) {
			t.Errorf("%s: %v, want %s", name, err, tt.code)
		}
	}
}

// TestHR706_ReadLimitsTemplateIsAValidAccessRule: the read-limits template
// is one valid read rule; nothing applies it unless a grant names it (FD6).
//
// Covers: HR-706
func TestHR706_ReadLimitsTemplateIsAValidAccessRule(t *testing.T) {
	raw, err := os.ReadFile("../../../templates/read-limits/grant.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Limits json.RawMessage `json:"limits"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	l, err := DecodeLimits(doc.Limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.validate(true); err != nil || len(l.Budgets) != 1 || l.Budgets[0].Access != "read" || l.Budgets[0].MaxCount == "" {
		t.Fatalf("template %+v: %v", l, err)
	}
}
