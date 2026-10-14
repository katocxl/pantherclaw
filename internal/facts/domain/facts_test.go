// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	org = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")
	now = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
)

func provider() Provider {
	return Provider{
		ID: ids.NewV7(), Org: org, Name: "billing.system", ServiceAccountID: ids.NewV7(), State: ProviderActive,
		Facts: []Declaration{
			{Name: "payments.charge.refundable", Type: TypeBoolean, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
			{Name: "payments.charge.refunded", Type: TypeMoney, SubjectType: "payments.charge", MaxLag: 5 * time.Minute},
		},
	}
}

func obs(name, value string, at time.Time) Observation {
	return Observation{Name: name, SubjectType: "payments.charge", SubjectID: "ch_1", Value: jsontext.Value(value), ObservedAt: at}
}

func TestHR160_FactsOnlyFromTheirRegisteredProvider(t *testing.T) {
	p := provider()
	f, err := Accept(p, obs("payments.charge.refundable", `{"bool": true}`, now.Add(-time.Minute)), now, nil)
	if err != nil || !f.Value.Bool || f.ProviderID != p.ID || !f.RecordedAt.Equal(now) {
		t.Fatalf("Accept = %+v, %v", f, err)
	}
	disabled := p
	disabled.State = ProviderDisabled
	if _, err := Accept(disabled, obs("payments.charge.refundable", `{"bool": true}`, now), now, nil); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a disabled provider: %v", err)
	}
	if _, err := Accept(p, obs("payments.charge.disputed", `{"bool": true}`, now), now, nil); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a fact the provider is not registered for: %v", err)
	}
	wrongSubject := obs("payments.charge.refundable", `{"bool": true}`, now)
	wrongSubject.SubjectType = "payments.customer"
	if _, err := Accept(p, wrongSubject, now, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a fact about another subject type: %v", err)
	}
}

func TestHR160_ObservationTimesAreBoundedByTheDatabaseClock(t *testing.T) {
	p := provider()
	if _, err := Accept(p, obs("payments.charge.refundable", `{"bool": true}`, now.Add(time.Minute)), now, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an observation from the future: %v", err)
	}
	f, err := Accept(p, obs("payments.charge.refundable", `{"bool": true}`, now.Add(2*time.Second)), now, nil)
	if err != nil || !f.ObservedAt.Equal(now) {
		t.Fatalf("a slightly fast provider clock is recorded at the database time: %+v %v", f, err)
	}
	if _, err := Accept(p, obs("payments.charge.refundable", `{"bool": true}`, now.Add(-6*time.Minute)), now, nil); !errors.Is(err, ErrStale) {
		t.Fatalf("an observation older than its lag: %v", err)
	}
	newer := Fact{ObservedAt: now.Add(-time.Minute)}
	if _, err := Accept(p, obs("payments.charge.refundable", `{"bool": false}`, now.Add(-2*time.Minute)), now, &newer); !errors.Is(err, ErrStale) {
		t.Fatalf("an older observation replaced a newer one: %v", err)
	}
}

func TestHR101_FactValuesAreStrictlyTyped(t *testing.T) {
	good := map[Type]string{
		TypeBoolean: `{"bool": false}`, TypeInteger: `{"int": "-42"}`, TypeDecimal: `{"decimal": "1.5"}`,
		TypeMoney: `{"amount": "30.00", "currency": "USD"}`, TypeIdentifier: `{"id": "acct_1"}`, TypeTimestamp: `{"time": "2026-10-09T11:00:00Z"}`,
	}
	for typ, raw := range good {
		if _, err := DecodeValue(typ, jsontext.Value(raw)); err != nil {
			t.Errorf("%s %s: %v", typ, raw, err)
		}
	}
	bad := map[Type]string{
		TypeBoolean:    `{"bool": "true"}`,
		TypeInteger:    `{"int": 42}`,
		TypeDecimal:    `{"decimal": "1e3"}`,
		TypeMoney:      `{"amount": "30.001", "currency": "USD"}`,
		TypeIdentifier: `{"id": "ch_` + string(rune(0x202e)) + `"}`,
		TypeTimestamp:  `{"time": "yesterday"}`,
	}
	for typ, raw := range bad {
		if _, err := DecodeValue(typ, jsontext.Value(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s %s accepted: %v", typ, raw, err)
		}
	}
	if _, err := DecodeValue(TypeBoolean, jsontext.Value(`{"bool": true, "id": "x"}`)); !errors.Is(err, ErrInvalid) {
		t.Error("a value with two fields was accepted")
	}
	if _, err := DecodeValue(TypeBoolean, jsontext.Value(`{"bool": true, "extra": 1}`)); !errors.Is(err, ErrInvalid) {
		t.Error("an unknown field was accepted")
	}
}

func TestProviderValidation(t *testing.T) {
	if err := provider().Validate(nil); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(p *Provider){
		"no facts":           func(p *Provider) { p.Facts = nil },
		"undotted fact name": func(p *Provider) { p.Facts[0].Name = "refundable" },
		"underscore collision": func(p *Provider) {
			p.Facts = append(p.Facts, Declaration{Name: "payments_charge.refundable", Type: TypeBoolean, SubjectType: "payments.charge", MaxLag: time.Minute})
		},
		"unknown type":      func(p *Provider) { p.Facts[0].Type = "string" },
		"lag over a day":    func(p *Provider) { p.Facts[0].MaxLag = 25 * time.Hour },
		"no service acount": func(p *Provider) { p.ServiceAccountID = ids.UUID{} },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			p := provider()
			mutate(&p)
			if err := p.Validate(nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
	taken := func(n string) bool { return n == "payments.charge.refunded" }
	if err := provider().Validate(taken); !errors.Is(err, ErrInvalid) {
		t.Fatal("two providers for one fact")
	}
}

func TestEvaluateReportsMissingAndStaleWithTheStrictestAge(t *testing.T) {
	recorded := map[string]Fact{
		"payments.charge.refundable": {Name: "payments.charge.refundable", ObservedAt: now.Add(-2 * time.Minute)},
	}
	checks := Evaluate([]Requirement{
		{Name: "payments.charge.refundable", MaxAge: 5 * time.Minute, Source: "definition"},
		{Name: "payments.charge.refundable", MaxAge: time.Minute, Source: "rule fresh-only"},
		{Name: "payments.charge.refunded", MaxAge: time.Hour, Source: "rule cap"},
	}, recorded, now)
	if len(checks) != 2 {
		t.Fatalf("checks %+v", checks)
	}
	if c := checks[0]; c.Requirement.Name != "payments.charge.refundable" || c.Status != Stale || c.Requirement.MaxAge != time.Minute || c.Age != 2*time.Minute {
		t.Fatalf("strictest age not applied: %+v", c)
	}
	if c := checks[1]; c.Status != Missing {
		t.Fatalf("missing fact: %+v", c)
	}
}

func TestDigestIsCanonical(t *testing.T) {
	p := provider()
	a, _ := Accept(p, obs("payments.charge.refundable", `{"bool": true}`, now), now, nil)
	b, _ := Accept(p, obs("payments.charge.refunded", `{"amount": "10.00", "currency": "USD"}`, now), now, nil)
	if Digest([]Fact{a, b}) != Digest([]Fact{b, a}) {
		t.Fatal("the digest depends on order")
	}
	c := a
	c.Value.Bool = false
	if Digest([]Fact{a, b}) == Digest([]Fact{c, b}) {
		t.Fatal("the digest ignores the value")
	}
}

func FuzzFactValue(f *testing.F) {
	for _, s := range []string{`{"bool": true}`, `{"int": "1"}`, `{"amount": "1", "currency": "EUR"}`, `{"time": "2026-01-01T00:00:00Z"}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		for _, typ := range types {
			v, err := DecodeValue(typ, jsontext.Value(raw))
			if err == nil && v.Type != typ {
				t.Fatalf("decoded %s as %s", typ, v.Type)
			}
		}
	})
}

// TestAnUnreadFactIsMissing (the coordinator's decision Q11): an object
// fact its provider reported unread counts as missing, with why, however
// fresh, so no requirement is met by it.
func TestAnUnreadFactIsMissing(t *testing.T) {
	now := time.Now()
	recorded := map[string]Fact{"github.pull.head": {
		Name: "github.pull.head", ObservedAt: now, Value: Value{Type: TypeObject, Object: map[string]any{UnreadMember: "no read token"}},
	}}
	got := Evaluate([]Requirement{{Name: "github.pull.head", MaxAge: time.Minute, Source: "definition"}}, recorded, now)
	if len(got) != 1 || got[0].Status != Missing || got[0].Unread != "no read token" || got[0].Fact != nil {
		t.Fatalf("%+v", got)
	}
}
