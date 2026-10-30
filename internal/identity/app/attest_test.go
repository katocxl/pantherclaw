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

// TestAttestationOrgReadsTheAWSAudienceHeader: a signed AWS request names
// its org in the X-Pantherclaw-Audience header (D121).
func TestAttestationOrgReadsTheAWSAudienceHeader(t *testing.T) {
	org := ids.New[ids.Org]()
	tok, err := issuers.AWSRequest{Headers: map[string]string{"x-pantherclaw-audience": "pantherclaw:" + org.String()}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got := AttestationOrg(tok); got != org {
		t.Errorf("org = %v, want %v", got, org)
	}
	bad, _ := issuers.AWSRequest{Headers: map[string]string{"x-pantherclaw-audience": org.String()}}.Encode()
	if !AttestationOrg(bad).IsZero() || !AttestationOrg("not-base64!").IsZero() {
		t.Error("an AWS request without pantherclaw:<org> named an org")
	}
}

type fakeEntra map[string]ids.OrgID

func (f fakeEntra) OrgOf(app string) ids.OrgID                { return f[app] }
func (f fakeEntra) Allowed(_, app string, org ids.OrgID) bool { return f[app] == org }
func (f fakeEntra) Verify(context.Context, string, ids.OrgID, string) ([]byte, error) {
	return nil, errors.New("unused")
}

// TestHR469_AzureOrgComesOnlyFromThePinnedApp: an Azure token's org is the
// one the operator pinned to its audience app, never a pantherclaw:<org>
// audience; every other kind still reads pantherclaw:<org> and never an
// app id (HR-140).
// Covers: PN-002.3
func TestHR469_AzureOrgComesOnlyFromThePinnedApp(t *testing.T) {
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	const app = "00001111-aaaa-2222-bbbb-3333cccc4444"
	s := (&Service{}).WithAttestors(Attestors{Entra: fakeEntra{app: org}})
	for aud, want := range map[string]ids.OrgID{
		app: org, "api://" + app: org, "pantherclaw:" + other.String(): {}, "00001111-aaaa-2222-bbbb-3333cccc4445": {},
	} {
		if got := s.AttestationOrg(Attestation{Kind: issuers.KindAzureMI, Token: unsigned(`{"aud":"` + aud + `"}`)}); got != want {
			t.Errorf("azure_mi aud %q: org %v, want %v", aud, got, want)
		}
	}
	for _, k := range []issuers.Kind{issuers.KindGitHub, issuers.KindGitLab, issuers.KindSPIFFE, issuers.KindGCP} {
		if got := s.AttestationOrg(Attestation{Kind: k, Token: unsigned(`{"aud":"` + app + `"}`)}); !got.IsZero() {
			t.Errorf("%s with an app id audience named org %v", k, got)
		}
		if got := s.AttestationOrg(Attestation{Kind: k, Token: unsigned(`{"aud":"pantherclaw:` + other.String() + `"}`)}); got != other {
			t.Errorf("%s: org %v", k, got)
		}
	}
	if !(&Service{}).AttestationOrg(Attestation{Kind: issuers.KindAzureMI, Token: unsigned(`{"aud":"` + app + `"}`)}).IsZero() {
		t.Error("an org without entra_apps")
	}
	b := Binding{GitHub: &issuers.GitHubBinding{}}
	if b.audience(org) != "pantherclaw:"+org.String() || (Binding{AzureMI: &issuers.AzureMIBinding{AppID: app}}).audience(org) != app {
		t.Error("entry audiences")
	}
}
