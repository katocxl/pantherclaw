// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"testing"
)

func scopeRule(kind ConstraintKind, param string, vs ...string) *Rule {
	r := rule("scope", Constrain)
	r.Constraint = &Constraint{Kind: kind, Param: param, Values: vs}
	return r
}

// TestHR302_DataScopeRules: record_scope names a record key and 1..100
// values, data_classes only public, internal and pii (never secret); fewer
// values tighten, a different key is unknown, and the bundle says it needs
// the edition that offers data scoping (G0 M14 D11).
func TestHR302_DataScopeRules(t *testing.T) {
	for name, r := range map[string]*Rule{
		"records": scopeRule(RecordScope, "customer", "cus_1"),
		"classes": scopeRule(DataClasses, "", "public", "internal"),
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !bundleOf(r).HasScopeRules() {
			t.Errorf("%s: no scope rule", name)
		}
	}
	if bundleOf(rule("c", Constrain)).HasScopeRules() {
		t.Error("count_max is a scope rule")
	}
	for name, r := range map[string]*Rule{
		"records without key": scopeRule(RecordScope, "", "cus_1"),
		"records quoted key":  scopeRule(RecordScope, "Customer", "cus_1"),
		"records no values":   scopeRule(RecordScope, "customer"),
		"records odd value":   scopeRule(RecordScope, "customer", "cus 1"),
		"classes secret":      scopeRule(DataClasses, "", "public", "secret"),
		"classes with param":  scopeRule(DataClasses, "customer", "public"),
		"classes unknown":     scopeRule(DataClasses, "", "confidential"),
	} {
		if err := r.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, c := range []struct {
		name      string
		from, to  *Rule
		direction Direction
	}{
		{"fewer records", scopeRule(RecordScope, "customer", "a", "b"), scopeRule(RecordScope, "customer", "a"), Tighter},
		{"more records", scopeRule(RecordScope, "customer", "a"), scopeRule(RecordScope, "customer", "a", "b"), Looser},
		{"another key", scopeRule(RecordScope, "customer", "a"), scopeRule(RecordScope, "tenant", "a"), Unknown},
		{"fewer classes", scopeRule(DataClasses, "", "public", "pii"), scopeRule(DataClasses, "", "public"), Tighter},
		{"more classes", scopeRule(DataClasses, "", "public"), scopeRule(DataClasses, "", "public", "pii"), Looser},
	} {
		if d := Compare(bundleOf(c.from), bundleOf(c.to)); d.Direction != c.direction {
			t.Errorf("%s: %s", c.name, d.Direction)
		}
	}
}
