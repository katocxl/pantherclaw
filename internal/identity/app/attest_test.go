// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func unsigned(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(payload)) + ".sig"
}

// TestHR143_AttestationOrgNeedsExactlyOneOrgAudience: the unverified
// audience only routes the request, and only when it names one org.
func TestHR143_AttestationOrgNeedsExactlyOneOrgAudience(t *testing.T) {
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	if got := AttestationOrg(unsigned(`{"aud":"pantherclaw:` + org.String() + `"}`)); got != org {
		t.Fatalf("single audience: %v", got)
	}
	if got := AttestationOrg(unsigned(`{"aud":["sigstore","pantherclaw:` + org.String() + `"]}`)); got != org {
		t.Fatalf("audience list: %v", got)
	}
	for name, tok := range map[string]string{
		"two orgs":   unsigned(`{"aud":["pantherclaw:` + org.String() + `","pantherclaw:` + other.String() + `"]}`),
		"no org":     unsigned(`{"aud":"pantherclaw:acme"}`),
		"not a JWS":  "pantherclaw:" + org.String(),
		"oversized":  unsigned(`{"aud":"pantherclaw:` + org.String() + `","x":"` + strings.Repeat("a", maxAttestation) + `"}`),
		"duplicates": unsigned(`{"aud":"pantherclaw:` + org.String() + `","aud":"x"}`),
	} {
		if got := AttestationOrg(tok); !got.IsZero() {
			t.Errorf("%s: routed to %v", name, got)
		}
	}
}

// TestHR147_EnrollmentPicksOneAgentsEntry: an attestation that matches
// entries of two agents is ambiguous; an enrollment token narrows it to its
// agent; an auto-admitting entry wins over one that does not.
func TestHR147_EnrollmentPicksOneAgentsEntry(t *testing.T) {
	a1, a2 := ids.NewV7(), ids.NewV7()
	cand := func(agent ids.UUID, auto bool) attested {
		return attested{rev: dbq.PcTrustedIssuer{ID: ids.NewV7(), EntryID: ids.NewV7(), AgentID: agent, AutoAdmit: auto}}
	}
	plain, auto, elsewhere := cand(a1, false), cand(a1, true), cand(a2, true)
	if got, err := choose([]attested{plain, auto}, nil); err != nil || got.rev.ID != auto.rev.ID {
		t.Fatalf("one agent: %+v, %v", got.rev, err)
	}
	if _, err := choose([]attested{plain, elsewhere}, nil); !errors.Is(err, pap.Err(pap.CodeAttestationLow)) {
		t.Fatalf("two agents: %v", err)
	}
	if got, err := choose([]attested{plain, elsewhere}, &a1); err != nil || got.rev.ID != plain.rev.ID {
		t.Fatalf("narrowed by the enrollment token: %+v, %v", got.rev, err)
	}
	if _, err := choose([]attested{elsewhere}, &a1); err == nil {
		t.Fatal("matched another agent's entry")
	}
}

// TestHR465_UnknownAttestationKindsAreRefused: a kind with no preset is
// refused before any entry, issuer or cluster is consulted, never mapped to
// a default preset.
// Covers: PN-002.3
func TestHR465_UnknownAttestationKindsAreRefused(t *testing.T) {
	s := &Service{} // no pool: a refusal must come before any lookup
	for _, k := range []issuers.Kind{"", "oidc", "GITHUB_ACTIONS", "github_actions "} {
		_, err := s.attest(context.Background(), ids.New[ids.Org](), Attestation{Kind: k, Token: unsigned(`{}`)})
		if !errors.Is(err, pap.Err(pap.CodeAttestationLow)) {
			t.Errorf("kind %q: %v, want attestation_insufficient", k, err)
		}
	}
}
