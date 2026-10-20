// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"slices"
	"testing"
)

func scoped(key string, values []string, classes ...string) Bounds {
	sb := ScopeBound{}
	if key != "" {
		sb.Records = &RecordScope{Key: key, Values: values}
	}
	if len(classes) > 0 {
		sb.Classes = &Match{IDs: classes, Prefixes: []string{}}
	}
	return Bounds{Scope: map[string]ScopeBound{"shop.rows.read": sb}}
}

// TestHR302_ScopeBoundsAreValidated: a scope names exact operations, a
// lower-case record key with 1..100 distinct exact values, and classes
// among public, internal and pii; secret is never allowed (G0 M14 D11).
func TestHR302_ScopeBoundsAreValidated(t *testing.T) {
	if err := scoped("customer", []string{"cus_1"}, "public", "pii").Validate(); err != nil {
		t.Fatal(err)
	}
	many := make([]string, MaxScopeRecords+1)
	for i := range many {
		many[i] = "cus_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	for name, b := range map[string]Bounds{
		"secret":         scoped("", nil, "public", "secret"),
		"unknown class":  scoped("", nil, "confidential"),
		"class prefix":   {Scope: map[string]ScopeBound{"shop.rows.read": {Classes: &Match{Prefixes: []string{"p"}}}}},
		"no values":      scoped("customer", []string{}),
		"value twice":    scoped("customer", []string{"cus_1", "cus_1"}),
		"too many":       scoped("customer", many),
		"quoted key":     scoped(`"Customer"`, []string{"cus_1"}),
		"empty bound":    {Scope: map[string]ScopeBound{"shop.rows.read": {}}},
		"operation glob": {Scope: map[string]ScopeBound{"shop.*": {Classes: &Match{IDs: []string{"public"}}}}},
	} {
		if err := b.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestT144_ScopeCannotEscapeThroughDelegationOrRevision: a delegated grant
// inherits its parent's scope and can only narrow it (a scope it leaves
// out is the parent's, a wider one is refused); a revision that widens a
// scope is a widening revision; envelopes and ancestors meet in the
// effective scope; two record keys allow no record (G0 M14 D11).
func TestT144_ScopeCannotEscapeThroughDelegationOrRevision(t *testing.T) {
	parent := scoped("customer", []string{"cus_1", "cus_2"}, "public", "internal")
	child := Bounds{}.Inherit(parent)
	if v := child.Within(parent); v != nil || !slices.Equal(child.Scope["shop.rows.read"].Records.Values, []string{"cus_1", "cus_2"}) {
		t.Fatalf("an inherited scope: %v %+v", v, child.Scope)
	}
	for name, c := range map[string]Bounds{
		"another record":  scoped("customer", []string{"cus_1", "cus_3"}, "public"),
		"another key":     scoped("tenant", []string{"cus_1"}, "public"),
		"pii":             scoped("customer", []string{"cus_1"}, "public", "pii"),
		"no record scope": {Scope: map[string]ScopeBound{"shop.rows.read": {Classes: &Match{IDs: []string{"public"}}}}},
		"no scope":        {},
	} {
		if v := c.Within(parent); v == nil {
			t.Errorf("%s: a delegated scope wider than its parent's was within it", name)
		}
	}
	narrow := scoped("customer", []string{"cus_2"}, "public")
	if v := narrow.Inherit(parent).Within(parent); v != nil {
		t.Fatalf("a narrower scope: %v", v)
	}

	cur := Grant{ID: NewGrantID(), Revision: 1, State: StateActive, Bounds: parent}
	next := cur
	next.Revision, next.Bounds = 2, scoped("customer", []string{"cus_1", "cus_2", "cus_3"}, "public", "internal")
	if rev, err := CompareRevision(cur, next); err != nil || !rev.Widens {
		t.Fatalf("a wider scope revision: %+v %v", rev, err)
	}
	next.Bounds = narrow
	if rev, err := CompareRevision(cur, next); err != nil || rev.Widens {
		t.Fatalf("a narrower scope revision: %+v %v", rev, err)
	}

	envelope := scoped("customer", []string{"cus_2", "cus_9"}, "public", "pii")
	eff := Chain{Envelopes: []Envelope{{Bounds: envelope}}, Grants: []Grant{{Bounds: parent}}}.Effective().Scope["shop.rows.read"]
	if !slices.Equal(eff.Records.Values, []string{"cus_2"}) || !slices.Equal(eff.Classes.IDs, []string{"public"}) {
		t.Fatalf("effective scope %+v %+v", eff.Records, eff.Classes)
	}
	keys := Chain{Grants: []Grant{{Bounds: parent}, {Bounds: scoped("tenant", []string{"t1"})}}}.Effective().Scope["shop.rows.read"]
	if keys.Records == nil || len(keys.Records.Values) != 0 {
		t.Fatalf("two record keys: %+v", keys.Records)
	}
}
