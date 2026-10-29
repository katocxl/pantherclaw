// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
)

const spID = "spiffe://prod.acme.test/ns/agents/sa/runner"

func spBinding() issuers.SPIFFEBinding {
	return issuers.SPIFFEBinding{TrustDomain: "prod.acme.test", SPIFFEID: spID}
}

func spClaims(t *testing.T, mutate func(*string)) issuers.SPIFFEClaims {
	t.Helper()
	payload := `{"sub":"` + spID + `","aud":["pantherclaw:` + org.String() + `"],"exp":1,"iat":0}`
	if mutate != nil {
		mutate(&payload)
	}
	c, err := issuers.ParseSPIFFEClaims([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSPIFFEMatchesTheExactWorkload(t *testing.T) {
	m, err := issuers.MatchSPIFFE(spBinding(), org, "prod.acme.test", spClaims(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Binding.Equal(issuers.Binding{"spiffe_id": spID}) || spBinding().Issuer() != "spiffe://prod.acme.test" {
		t.Fatalf("match = %+v", m)
	}
}

// TestHR462_SPIFFEPresetRules: the sub is exactly the pinned SPIFFE ID and
// in the trust domain whose bundle verified the token, and the audience is
// exactly the org's — whatever the entry says.
// Covers: PN-002.3
func TestHR462_SPIFFEPresetRules(t *testing.T) {
	for name, mutate := range map[string]func(*string){
		"other workload":          replace(spID, "spiffe://prod.acme.test/ns/agents/sa/other"),
		"child path":              replace(spID, spID+"/x"),
		"other trust domain":      replace(spID, "spiffe://evil.test/ns/agents/sa/runner"),
		"not a SPIFFE ID":         replace(spID, "https://prod.acme.test/ns/agents/sa/runner"),
		"other org":               replace(org.String(), "00000000-0000-7000-8000-000000000000"),
		"second audience":         replace(`"]`, `","other"]`),
		"no audience":             replace(`"aud":["pantherclaw:`+org.String()+`"],`, ``),
		"dot segment":             replace(spID, "spiffe://prod.acme.test/ns/../sa/runner"),
		"upper-case trust domain": replace(spID, "spiffe://PROD.acme.test/ns/agents/sa/runner"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := issuers.MatchSPIFFE(spBinding(), org, "prod.acme.test", spClaims(t, mutate)); !errors.Is(err, issuers.ErrRejected) {
				t.Fatalf("err = %v, want rejection", err)
			}
		})
	}
	// One trust domain's bundle never vouches for another's workload,
	// even one an entry pins.
	other := issuers.SPIFFEBinding{TrustDomain: "evil.test", SPIFFEID: "spiffe://evil.test/w"}
	c := spClaims(t, replace(spID, "spiffe://evil.test/w"))
	if _, err := issuers.MatchSPIFFE(other, org, "prod.acme.test", c); !errors.Is(err, issuers.ErrRejected) {
		t.Errorf("cross trust domain: %v", err)
	}
	for name, b := range map[string]issuers.SPIFFEBinding{
		"prefix":            {TrustDomain: "prod.acme.test", SPIFFEID: "spiffe://prod.acme.test/ns/*"},
		"trust domain only": {TrustDomain: "prod.acme.test", SPIFFEID: "spiffe://prod.acme.test"},
		"other domain":      {TrustDomain: "prod.acme.test", SPIFFEID: "spiffe://evil.test/w"},
		"port":              {TrustDomain: "prod.acme.test", SPIFFEID: "spiffe://prod.acme.test:443/w"},
		"query":             {TrustDomain: "prod.acme.test", SPIFFEID: "spiffe://prod.acme.test/w?x=1"},
		"empty segment":     {TrustDomain: "prod.acme.test", SPIFFEID: "spiffe://prod.acme.test//w"},
	} {
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

// TestHR141_SPIFFEChangesAreWidenings: a new or changed SPIFFE ID needs
// activation.
// Covers: PN-002.3
func TestHR141_SPIFFEChangesAreWidenings(t *testing.T) {
	b := spBinding()
	if w := b.Widening(&b); len(w) != 0 {
		t.Errorf("same binding widens: %v", w)
	}
	n := b
	n.SPIFFEID = "spiffe://prod.acme.test/other"
	if len(n.Widening(&b)) == 0 || len(b.Widening(nil)) == 0 {
		t.Error("a new or changed SPIFFE ID must need activation")
	}
}
