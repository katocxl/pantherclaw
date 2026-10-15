// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
)

func bundleOf(rules ...*Rule) *Bundle {
	b := &Bundle{ID: "refunds", Version: 1}
	for _, r := range rules {
		b.Rules = append(b.Rules, *r)
	}
	return b
}

func with(r *Rule, edit func(*Rule)) *Rule {
	c := *r
	c.Operations = slices.Clone(r.Operations)
	c.Environments = slices.Clone(r.Environments)
	c.Facts = slices.Clone(r.Facts)
	if r.Approval != nil {
		a := *r.Approval
		c.Approval = &a
	}
	if r.StepUp != nil {
		s := *r.StepUp
		c.StepUp = &s
	}
	if r.Constraint != nil {
		k := *r.Constraint
		k.Values = slices.Clone(r.Constraint.Values)
		c.Constraint = &k
	}
	if r.Labels != nil {
		c.Labels = map[string]string{}
		for k, v := range r.Labels {
			c.Labels[k] = v
		}
	}
	edit(&c)
	return &c
}

func amount(limit string) *Rule {
	r := rule("cap", Constrain)
	r.Constraint = &Constraint{Kind: AmountMax, Param: "amount", Max: limit, Currency: "USD"}
	return r
}

func values(kind ConstraintKind, vs ...string) *Rule {
	r := rule("set", Constrain)
	r.Constraint = &Constraint{Kind: kind, Values: vs}
	if kind == AllowedValues {
		r.Constraint.Param = "currency"
	}
	return r
}

func emergency(id string, k Kind) *Rule {
	r := rule(id, k)
	r.Labels = map[string]string{EmergencyLabel: "true"}
	return r
}

// TestCompareClassifiesEveryChange is D3's exhaustive table: each row is
// one change and the direction it must get, alone and as the diff's.
func TestCompareClassifiesEveryChange(t *testing.T) {
	appr := rule("hold", RequireApproval)
	appr.Approval.DeadlineSeconds = 3600
	step := rule("step", RequireStepUp)
	step.StepUp.DeadlineSeconds = 3600
	verify := rule("verify", Constrain)
	verify.Constraint = &Constraint{Kind: Verify, Level: defs.LevelDomainEffect}
	facts := with(rule("f", Forbid), func(r *Rule) { r.Facts = []FactRef{{Name: "risk.score", MaxAgeSeconds: 60}} })
	scoped := with(rule("s", Forbid), func(r *Rule) {
		r.Operations = []string{"payments.refund.create"}
		r.Environments = []string{"prod"}
	})
	ann := rule("note", Annotate)

	type row struct {
		name       string
		base, next *Bundle
		want       Direction
		field      string
	}
	rows := []row{
		{"no policy to a forbid", nil, bundleOf(rule("f", Forbid)), Tighter, ""},
		{"forbid added", bundleOf(), bundleOf(rule("f", Forbid)), Tighter, ""},
		{"forbid removed", bundleOf(rule("f", Forbid)), bundleOf(), Looser, ""},
		{"annotate added", bundleOf(), bundleOf(ann), Neutral, ""},
		{"annotate removed", bundleOf(ann), bundleOf(), Neutral, ""},
		{"annotate changed", bundleOf(ann), bundleOf(with(ann, func(r *Rule) { r.When = "false" })), Neutral, "when"},
		{"emergency annotate removed", bundleOf(emergency("e", Annotate)), bundleOf(), Looser, ""},
		{"emergency label removed", bundleOf(emergency("e", Annotate)), bundleOf(with(emergency("e", Annotate), func(r *Rule) { r.Labels = nil })), Looser, "labels.emergency"},
		{"emergency label added", bundleOf(ann), bundleOf(with(ann, func(r *Rule) { r.Labels[EmergencyLabel] = "true" })), Neutral, "labels"},
		{"summary text", bundleOf(rule("f", Forbid)), bundleOf(with(rule("f", Forbid), func(r *Rule) { r.Summary = "other" })), Neutral, "summary"},
		{"reason code", bundleOf(rule("f", Forbid)), bundleOf(with(rule("f", Forbid), func(r *Rule) { r.Reason = "OTHER_REASON" })), Neutral, "reason"},
		{"operations superset", bundleOf(scoped), bundleOf(with(scoped, func(r *Rule) { r.Operations = []string{"payments.*"} })), Tighter, "operations"},
		{"operations subset", bundleOf(with(scoped, func(r *Rule) { r.Operations = []string{"payments.*"} })), bundleOf(scoped), Looser, "operations"},
		{"operations disjoint", bundleOf(scoped), bundleOf(with(scoped, func(r *Rule) { r.Operations = []string{"shell.exec"} })), Unknown, "operations"},
		{"operations reordered", bundleOf(with(scoped, func(r *Rule) { r.Operations = []string{"a.b", "c.d"} })), bundleOf(with(scoped, func(r *Rule) { r.Operations = []string{"c.d", "a.b"} })), Neutral, "operations"},
		{"environments to all", bundleOf(scoped), bundleOf(with(scoped, func(r *Rule) { r.Environments = nil })), Tighter, "environments"},
		{"environments from all", bundleOf(with(scoped, func(r *Rule) { r.Environments = nil })), bundleOf(scoped), Looser, "environments"},
		{"environments superset", bundleOf(scoped), bundleOf(with(scoped, func(r *Rule) { r.Environments = []string{"prod", "staging"} })), Tighter, "environments"},
		{"environments other", bundleOf(scoped), bundleOf(with(scoped, func(r *Rule) { r.Environments = []string{"staging"} })), Unknown, "environments"},
		{"when text", bundleOf(rule("f", Forbid)), bundleOf(with(rule("f", Forbid), func(r *Rule) { r.When = "true " })), Unknown, "when"},
		{"constrain to forbid", bundleOf(kindRule(Constrain)), bundleOf(kindRule(Forbid)), Tighter, "kind"},
		{"approval to forbid", bundleOf(kindRule(RequireApproval)), bundleOf(kindRule(Forbid)), Tighter, "kind"},
		{"step-up to forbid", bundleOf(kindRule(RequireStepUp)), bundleOf(kindRule(Forbid)), Tighter, "kind"},
		{"constrain to approval", bundleOf(kindRule(Constrain)), bundleOf(kindRule(RequireApproval)), Tighter, "kind"},
		{"constrain to step-up", bundleOf(kindRule(Constrain)), bundleOf(kindRule(RequireStepUp)), Tighter, "kind"},
		{"forbid to approval", bundleOf(kindRule(Forbid)), bundleOf(kindRule(RequireApproval)), Looser, "kind"},
		{"forbid to constrain", bundleOf(kindRule(Forbid)), bundleOf(kindRule(Constrain)), Looser, "kind"},
		{"step-up to constrain", bundleOf(kindRule(RequireStepUp)), bundleOf(kindRule(Constrain)), Looser, "kind"},
		{"approval to step-up", bundleOf(kindRule(RequireApproval)), bundleOf(kindRule(RequireStepUp)), Unknown, "kind"},
		{"step-up to approval", bundleOf(kindRule(RequireStepUp)), bundleOf(kindRule(RequireApproval)), Unknown, "kind"},
		{"forbid to annotate", bundleOf(kindRule(Forbid)), bundleOf(with(kindRule(Annotate), func(r *Rule) { r.Labels = nil })), Unknown, "kind"},
		{"amount lower", bundleOf(amount("100.00")), bundleOf(amount("50.00")), Tighter, "constraint.max"},
		{"amount higher", bundleOf(amount("50.00")), bundleOf(amount("100.00")), Looser, "constraint.max"},
		{"amount same value", bundleOf(amount("50")), bundleOf(amount("50.00")), Neutral, "constraint.max"},
		{"amount currency", bundleOf(amount("50")), bundleOf(with(amount("50"), func(r *Rule) { r.Constraint.Currency = "EUR" })), Unknown, "constraint"},
		{"amount param", bundleOf(amount("50")), bundleOf(with(amount("50"), func(r *Rule) { r.Constraint.Param = "total" })), Unknown, "constraint"},
		{"constraint kind", bundleOf(kindRule(Constrain)), bundleOf(with(kindRule(Constrain), func(r *Rule) { r.Constraint.Kind = AmountMax })), Unknown, "constraint"},
		{"count lower", bundleOf(kindRule(Constrain)), bundleOf(with(kindRule(Constrain), func(r *Rule) { r.Constraint.Max = "10" })), Tighter, "constraint.max"},
		{"count higher", bundleOf(kindRule(Constrain)), bundleOf(with(kindRule(Constrain), func(r *Rule) { r.Constraint.Max = "1000" })), Looser, "constraint.max"},
		{"allowed values subset", bundleOf(values(AllowedValues, "usd", "eur")), bundleOf(values(AllowedValues, "usd")), Tighter, "constraint.values"},
		{"allowed values superset", bundleOf(values(AllowedValues, "usd")), bundleOf(values(AllowedValues, "usd", "eur")), Looser, "constraint.values"},
		{"allowed values other", bundleOf(values(AllowedValues, "usd")), bundleOf(values(AllowedValues, "eur")), Unknown, "constraint.values"},
		{"target set subset", bundleOf(values(TargetSet, "a", "b")), bundleOf(values(TargetSet, "a")), Tighter, "constraint.values"},
		{"target set superset", bundleOf(values(TargetSet, "a")), bundleOf(values(TargetSet, "a", "b")), Looser, "constraint.values"},
		{"destination set subset", bundleOf(values(DestinationSet, "a", "b")), bundleOf(values(DestinationSet, "b")), Tighter, "constraint.values"},
		{"destination set superset", bundleOf(values(DestinationSet, "b")), bundleOf(values(DestinationSet, "a", "b")), Looser, "constraint.values"},
		{"verify higher", bundleOf(verify), bundleOf(with(verify, func(r *Rule) { r.Constraint.Level = defs.LevelDownstream })), Tighter, "constraint.level"},
		{"verify lower", bundleOf(verify), bundleOf(with(verify, func(r *Rule) { r.Constraint.Level = defs.LevelFollowUp })), Looser, "constraint.level"},
		{"approval count up", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.Count = 2 })), Tighter, "approval.count"},
		{"approval count down", bundleOf(with(appr, func(r *Rule) { r.Approval.Count = 2 })), bundleOf(appr), Looser, "approval.count"},
		{"independent on", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.Independent = true })), Tighter, "approval.independent"},
		{"independent off", bundleOf(with(appr, func(r *Rule) { r.Approval.Independent = true })), bundleOf(appr), Looser, "approval.independent"},
		{"window on", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.Window = true })), Tighter, "approval.window"},
		{"window off", bundleOf(with(appr, func(r *Rule) { r.Approval.Window = true })), bundleOf(appr), Looser, "approval.window"},
		{"approval deadline shorter", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.DeadlineSeconds = 600 })), Tighter, "approval.deadline_seconds"},
		{"approval deadline longer", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.DeadlineSeconds = 7200 })), Looser, "approval.deadline_seconds"},
		{"approval deadline unset", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.DeadlineSeconds = 0 })), Unknown, "approval.deadline_seconds"},
		{"approval role", bundleOf(appr), bundleOf(with(appr, func(r *Rule) { r.Approval.Role = "release_approver" })), Unknown, "approval.role"},
		{"step-up subject", bundleOf(step), bundleOf(with(step, func(r *Rule) { r.StepUp.Subject = "principal" })), Unknown, "step_up.subject"},
		{"step-up method", bundleOf(step), bundleOf(with(step, func(r *Rule) { r.StepUp.Method = "other" })), Unknown, "step_up.method"},
		{"step-up deadline shorter", bundleOf(step), bundleOf(with(step, func(r *Rule) { r.StepUp.DeadlineSeconds = 600 })), Tighter, "step_up.deadline_seconds"},
		{"step-up deadline longer", bundleOf(step), bundleOf(with(step, func(r *Rule) { r.StepUp.DeadlineSeconds = 7200 })), Looser, "step_up.deadline_seconds"},
		{"fact added", bundleOf(rule("f", Forbid)), bundleOf(facts), Tighter, "facts"},
		{"fact removed", bundleOf(facts), bundleOf(rule("f", Forbid)), Looser, "facts"},
		{"fact max age lower", bundleOf(facts), bundleOf(with(facts, func(r *Rule) { r.Facts[0].MaxAgeSeconds = 30 })), Tighter, "facts"},
		{"fact max age higher", bundleOf(facts), bundleOf(with(facts, func(r *Rule) { r.Facts[0].MaxAgeSeconds = 120 })), Looser, "facts"},
		{"exceptable on", bundleOf(rule("f", Forbid)), bundleOf(with(rule("f", Forbid), func(r *Rule) { r.Exceptable = true })), Looser, "exceptable"},
		{"exceptable off", bundleOf(with(rule("f", Forbid), func(r *Rule) { r.Exceptable = true })), bundleOf(rule("f", Forbid)), Tighter, "exceptable"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			d := Compare(r.base, r.next)
			if d.Direction != r.want {
				t.Fatalf("direction %s, want %s: %+v", d.Direction, r.want, d.Changes)
			}
			if len(d.Changes) != 1 {
				t.Fatalf("want exactly one change, got %+v", d.Changes)
			}
			c := d.Changes[0]
			if c.Field != r.field || c.Direction != r.want || c.Sentence == "" {
				t.Fatalf("change %+v, want field %q", c, r.field)
			}
			if !strings.HasSuffix(c.Sentence, "("+strings.ToLower(string(r.want))+")") {
				t.Fatalf("sentence %q does not end with the direction", c.Sentence)
			}
			if d.Loosens() != (r.want == Looser || r.want == Unknown) {
				t.Fatalf("Loosens() = %v for %s", d.Loosens(), r.want)
			}
		})
	}
}

func TestCompareCombinesDirections(t *testing.T) {
	f, a := rule("f", Forbid), rule("a", RequireApproval)
	for name, c := range map[string]struct {
		base, next *Bundle
		want       Direction
	}{
		"identical":          {bundleOf(f, a), bundleOf(f, a), Neutral},
		"tighter + neutral":  {bundleOf(a), bundleOf(with(a, func(r *Rule) { r.Summary = "x" }), f), Tighter},
		"tighter + looser":   {bundleOf(a), bundleOf(f), Looser},
		"tighter + unknown":  {bundleOf(a), bundleOf(with(a, func(r *Rule) { r.When = "false" }), f), Unknown},
		"looser + unknown":   {bundleOf(a, f), bundleOf(with(a, func(r *Rule) { r.When = "false" })), Looser},
		"tests only":         {bundleOf(f), withTests(bundleOf(f), testCase("t1")), Neutral},
		"rules order change": {bundleOf(f, a), bundleOf(a, f), Neutral},
	} {
		if got := Compare(c.base, c.next).Direction; got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

func TestCompareSentences(t *testing.T) {
	d := Compare(bundleOf(amount("50.00")), bundleOf(with(amount("100.00"), func(r *Rule) { r.ID = "cap" })))
	want := "Rule cap: constraint limit 50.00 USD → 100.00 USD (looser)"
	if d.Changes[0].Sentence != want {
		t.Fatalf("sentence %q, want %q", d.Changes[0].Sentence, want)
	}
	tests := Compare(withTests(bundleOf(), testCase("a"), testCase("b")), withTests(bundleOf(), testCase("b"), func() TestCase {
		tc := testCase("a")
		tc.Summary = "changed"
		return tc
	}(), testCase("c")))
	var got []string
	for _, c := range tests.Changes {
		got = append(got, c.Sentence)
	}
	if want := []string{"Test a changed (neutral)", "Test c added (neutral)"}; !slices.Equal(got, want) {
		t.Fatalf("test sentences %q, want %q", got, want)
	}
}

func testCase(id string) TestCase {
	return TestCase{
		ID: id, Summary: "case " + id,
		Action: TestAction{Operation: "payments.refund.create", Params: jsontext.Value(`{"amount":"10.00"}`)},
		Expect: TestExpect{Decision: "ALLOW", Reason: "GRANTED"},
	}
}

func withTests(b *Bundle, tcs ...TestCase) *Bundle {
	b.Tests = tcs
	return b
}

func TestBundleTestsValidation(t *testing.T) {
	ok := withTests(bundleOf(rule("f", Forbid)), testCase("a"), testCase("b"))
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	many := make([]TestCase, MaxTests+1)
	for i := range many {
		many[i] = testCase("t" + strconv.Itoa(i))
	}
	for name, tcs := range map[string][]TestCase{
		"duplicate id": {testCase("a"), testCase("a")},
		"bad id":       {testCase("A")},
		"empty id":     {testCase("")},
		"too many":     many,
	} {
		b := withTests(bundleOf(rule("f", Forbid)), tcs...)
		if err := b.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := withTests(bundleOf(rule("f", Forbid)), many[:MaxTests]...).Validate(); err != nil {
		t.Fatalf("%d tests refused: %v", MaxTests, err)
	}
}

func TestContentDigest(t *testing.T) {
	b := withTests(bundleOf(rule("f", Forbid), amount("50.00")), testCase("a"))
	d := ContentDigest(b)
	v2 := *b
	v2.Version = 7
	if ContentDigest(&v2) != d {
		t.Fatal("the version number changed the content digest")
	}
	raw, err := json.Marshal(b, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	var back Bundle
	if err := json.Unmarshal(raw, &back, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if ContentDigest(&back) != d {
		t.Fatal("a stored and reloaded bundle has another digest")
	}
	// Params are canonicalized (JCS): whitespace and member order do not count.
	spaced := *b
	spaced.Tests = []TestCase{testCase("a")}
	spaced.Tests[0].Action.Params = jsontext.Value(`{ "amount" : "10.00" }`)
	if ContentDigest(&spaced) != d {
		t.Fatal("whitespace in params changed the digest")
	}
	if ContentDigest(bundleOf(rule("f", Forbid))) != ContentDigest(withTests(bundleOf(rule("f", Forbid)))) {
		t.Fatal("no tests and an empty test list differ")
	}
	for name, edit := range map[string]func(*Bundle){
		"rule":       func(b *Bundle) { b.Rules[0].When = "false" },
		"exceptable": func(b *Bundle) { b.Rules[0].Exceptable = true },
		"test":       func(b *Bundle) { b.Tests[0].Expect.Reason = "OTHER" },
		"id":         func(b *Bundle) { b.ID = "other" },
	} {
		c := *b
		c.Rules = slices.Clone(b.Rules)
		c.Tests = slices.Clone(b.Tests)
		edit(&c)
		if ContentDigest(&c) == d {
			t.Errorf("%s change kept the digest", name)
		}
	}
	r := b.Rules[0]
	if RuleDigest(r) != RuleDigest(*with(&r, func(*Rule) {})) {
		t.Fatal("rule digest is not deterministic")
	}
	if RuleDigest(r) == RuleDigest(*with(&r, func(r *Rule) { r.Exceptable = true })) {
		t.Fatal("rule digest ignores exceptable")
	}
}

func TestDefinitionsAndCatalogDigests(t *testing.T) {
	a, b := &defs.Definition{Digest: "sha256:aa"}, &defs.Definition{Digest: "sha256:bb"}
	if DefinitionsDigest([]*defs.Definition{a, b}) != DefinitionsDigest([]*defs.Definition{b, a}) {
		t.Fatal("definition order changed the digest")
	}
	if DefinitionsDigest([]*defs.Definition{a}) == DefinitionsDigest([]*defs.Definition{a, b}) {
		t.Fatal("an added definition kept the digest")
	}
	c1 := map[string]fdomain.Type{"risk.score": fdomain.Type("number"), "account.frozen": fdomain.Type("bool")}
	c2 := map[string]fdomain.Type{"risk.score": fdomain.Type("string"), "account.frozen": fdomain.Type("bool")}
	if CatalogDigest(c1) == CatalogDigest(c2) {
		t.Fatal("a fact type change kept the catalog digest")
	}
	if CatalogDigest(nil) != CatalogDigest(map[string]fdomain.Type{}) {
		t.Fatal("empty catalogs differ")
	}
}

func TestCarryEmergency(t *testing.T) {
	e1 := emergency("freeze", Annotate)
	e2 := emergency("stop", Annotate)
	current := bundleOf(rule("f", Forbid), e1, e2)
	oldE2 := with(e2, func(r *Rule) { r.Summary = "older" })
	target := withTests(bundleOf(rule("a", RequireApproval), oldE2), testCase("t"))
	out, carried := CarryEmergency(current, target)
	if !slices.Equal(carried, []string{"freeze", "stop"}) {
		t.Fatalf("carried %v", carried)
	}
	var ids []string
	for _, r := range out.Rules {
		ids = append(ids, r.ID)
	}
	if !slices.Equal(ids, []string{"a", "stop", "freeze"}) {
		t.Fatalf("rules %v", ids)
	}
	if out.Rules[1].Summary != e2.Summary {
		t.Fatal("the target's same-id rule was not replaced by the current emergency rule")
	}
	if len(out.Tests) != 1 || target.Rules[1].Summary != "older" || len(target.Rules) != 2 {
		t.Fatal("tests dropped or the target was modified")
	}
	for _, c := range Compare(current, out).Changes {
		if c.RuleID == "freeze" || c.RuleID == "stop" {
			t.Fatalf("a carried rollback still changes an emergency rule: %+v", c)
		}
	}
	if _, carried := CarryEmergency(nil, target); carried != nil {
		t.Fatal("nil current carried rules")
	}
	if _, carried := CarryEmergency(bundleOf(rule("f", Forbid)), target); carried != nil {
		t.Fatal("non-emergency rules carried")
	}
}

// kindRule is rule("k", k) with one reason code, so only the kind differs
// between two of them.
func kindRule(k Kind) *Rule {
	r := rule("k", k)
	r.Reason = "SAME_REASON"
	return r
}
