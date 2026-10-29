// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func classifier() Provider {
	return Provider{
		ID: ids.NewV7(), Org: org, Name: "catalog", ServiceAccountID: ids.NewV7(), State: ProviderActive,
		Facts: []Declaration{{Name: NameClassification, Type: TypeIdentifier, SubjectType: "crm.contact", MaxLag: time.Hour, Kind: KindClassification}},
	}
}

func classification(class, source, method string) Observation {
	return Observation{
		Name: NameClassification, SubjectType: "crm.contact", SubjectID: "c_1", Value: jsontext.Value(`{"id": "` + class + `"}`),
		ObservedAt: now.Add(-time.Minute), Source: source, Method: method,
	}
}

// TestHR435_ClassificationsNeedProvenance: a classification fact without a
// source and a method is refused, as is one whose value is not a data
// class; with both it is accepted and keeps them.
// Covers: F366
func TestHR435_ClassificationsNeedProvenance(t *testing.T) {
	p := classifier()
	if err := p.Validate(nil); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]Observation{
		"no provenance": classification("pii", "", ""),
		"no method":     classification("pii", "catalog", ""),
		"no source":     classification("pii", "", "rule"),
		"bad method":    classification("pii", "catalog", "guess"),
		"long source":   classification("pii", string(make([]byte, MaxSourceLen+1)), "rule"),
		"not a class":   classification("confidential", "catalog", "rule"),
	} {
		if _, err := Accept(p, o, now, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f, err := Accept(p, classification("pii", "catalog", "model"), now, nil)
	if err != nil || f.Class() != "pii" || f.Source != "catalog" || f.Method != "model" {
		t.Fatalf("Accept = %+v, %v", f, err)
	}
	bad := classifier()
	bad.Facts[0].Type = TypeBoolean
	if bad.Validate(nil) == nil {
		t.Error("a boolean classification was accepted")
	}
}

// TestHR441_OnlyTheBuiltinProviderDeclaresIdentityRisk: a service-account
// or gateway provider can neither declare pc.identity.risk nor take the
// built-in provider's name; the built-in provider is valid with neither a
// service account nor a gateway.
// Covers: F366
func TestHR441_OnlyTheBuiltinProviderDeclaresIdentityRisk(t *testing.T) {
	risk := Declaration{Name: NameIdentityRisk, Type: TypeObject, SubjectType: SubjectUser, MaxLag: MaxLagCeiling}
	p := provider()
	p.Facts = append(p.Facts, risk)
	if p.Validate(nil) == nil {
		t.Error("a service account's provider declared pc.identity.risk")
	}
	underscores := provider()
	underscores.Facts = append(underscores.Facts, Declaration{Name: "pc.identity_risk", Type: TypeObject, SubjectType: SubjectUser, MaxLag: time.Hour})
	if underscores.Validate(nil) == nil {
		t.Error("pc.identity_risk (the same policy name) was declared")
	}
	named := provider()
	named.Name = BuiltinProvider
	if named.Validate(nil) == nil {
		t.Error("a service account's provider took the built-in name")
	}
	builtin := Provider{ID: ids.NewV7(), Org: org, Name: BuiltinProvider, Builtin: true, State: ProviderActive, Facts: []Declaration{risk}}
	if err := builtin.Validate(nil); err != nil {
		t.Fatalf("the built-in provider: %v", err)
	}
	builtin.ServiceAccountID = ids.NewV7()
	if builtin.Validate(nil) == nil {
		t.Error("a built-in provider with a service account was accepted")
	}
}
