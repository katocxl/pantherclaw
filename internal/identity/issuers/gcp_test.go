// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
)

const gcpSA = "113524806285125460987"

func gcpClaims(t *testing.T, mutate func(*string)) issuers.GCPClaims {
	t.Helper()
	payload := `{"iss":"https://accounts.google.com","aud":"pantherclaw:` + org.String() + `","azp":"` + gcpSA + `",
		"sub":"` + gcpSA + `","email":"agent@acme-prod.iam.gserviceaccount.com","email_verified":true,"iat":0,"exp":1,
		"google":{"compute_engine":{"project_id":"acme-prod","project_number":349742,"instance_id":"5117906829363456",
		"instance_name":"runner","zone":"us-central1-a"}}}`
	if mutate != nil {
		mutate(&payload)
	}
	c, err := issuers.ParseGCPClaims([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGCPMatchesThePinnedServiceAccount(t *testing.T) {
	b := issuers.GCPBinding{ServiceAccountID: gcpSA, ProjectID: "acme-prod", InstanceID: "5117906829363456"}
	m, err := issuers.MatchGCP(b, org, gcpClaims(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Binding.Equal(issuers.Binding{"service_account_id": gcpSA}) {
		t.Fatalf("match = %+v", m)
	}
	// Without format=full there are no Compute Engine claims; a binding
	// that pins none still matches.
	if _, err := issuers.MatchGCP(issuers.GCPBinding{ServiceAccountID: gcpSA}, org, gcpClaims(t, replace(`"google":`, `"x":`))); err != nil {
		t.Errorf("standard format: %v", err)
	}
}

// TestHR463_GCPPresetRules: Google's issuer, the org's exact audience, the
// numeric service-account id and any pinned project or instance —
// whatever the entry says.
// Covers: PN-002.3
func TestHR463_GCPPresetRules(t *testing.T) {
	b := issuers.GCPBinding{ServiceAccountID: gcpSA, ProjectID: "acme-prod", InstanceID: "5117906829363456"}
	for name, mutate := range map[string]func(*string){
		"other issuer":           replace(`"iss":"https://accounts.google.com"`, `"iss":"https://evil.test"`),
		"issuer without scheme":  replace(`"iss":"https://accounts.google.com"`, `"iss":"accounts.google.com"`),
		"other org":              replace(org.String(), "00000000-0000-7000-8000-000000000000"),
		"other service account":  replace(`"sub":"`+gcpSA+`"`, `"sub":"113524806285125460988"`),
		"email instead of id":    replace(`"sub":"`+gcpSA+`"`, `"sub":"agent@acme-prod.iam.gserviceaccount.com"`),
		"other project":          replace(`"project_id":"acme-prod"`, `"project_id":"acme-dev"`),
		"other instance":         replace(`"instance_id":"5117906829363456"`, `"instance_id":"5117906829363457"`),
		"no compute engine data": replace(`"google":`, `"x":`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issuers.MatchGCP(b, org, gcpClaims(t, mutate)); !errors.Is(err, issuers.ErrRejected) {
				t.Fatalf("err = %v, want rejection", err)
			}
		})
	}
	for name, b := range map[string]issuers.GCPBinding{
		"email":        {ServiceAccountID: "agent@acme-prod.iam.gserviceaccount.com"},
		"empty":        {},
		"bad project":  {ServiceAccountID: gcpSA, ProjectID: "Acme"},
		"bad instance": {ServiceAccountID: gcpSA, InstanceID: "runner"},
	} {
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

func TestHR141_GCPRemovingAPinIsAWidening(t *testing.T) {
	prev := issuers.GCPBinding{ServiceAccountID: gcpSA, ProjectID: "acme-prod"}
	if w := (issuers.GCPBinding{ServiceAccountID: gcpSA}).Widening(&prev); len(w) == 0 {
		t.Error("removing the project pin must need activation")
	}
	if w := (issuers.GCPBinding{ServiceAccountID: gcpSA, ProjectID: "acme-prod", InstanceID: "1"}).Widening(&prev); len(w) != 0 {
		t.Errorf("adding a pin narrows: %v", w)
	}
}
