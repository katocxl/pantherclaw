// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var author = domain.Author{Type: "user", ID: "u1"}

func TestDraftValidate(t *testing.T) {
	ev := []domain.EvidenceRef{{Kind: domain.EvidenceTransaction, ID: ids.NewV7()}}
	q := ids.NewV7()
	ok := []domain.Draft{
		{Kind: domain.KindFact, Text: "f", Basis: domain.BasisObserved, Evidence: ev},
		{Kind: domain.KindHypothesis, Text: "h", Basis: domain.BasisHypothesis, Confidence: domain.ConfidenceLow, Alternatives: []string{"a"}},
		{Kind: domain.KindQuestion, Text: "q"},
		{Kind: domain.KindAnswer, Text: "a", Question: &q, Unresolved: true},
		{Kind: domain.KindNote, Text: "n"},
		{Kind: domain.KindImpact, Text: "i", Impact: domain.ImpactPotential, Evidence: ev},
		{Kind: domain.KindLink, Ref: &domain.Ref{Kind: domain.RefResponseAction, ID: ids.NewV7().String()}},
		{Kind: domain.KindOwner, OwnerRole: domain.RoleOwner, Owner: &q},
		{Kind: domain.KindOwner, OwnerRole: domain.RoleFollowUp, Owner: &q},
		{Kind: domain.KindState, State: domain.StateContained, NoContainmentNeeded: true, Reason: "r"},
		{Kind: domain.KindState, State: domain.StateClosed, Disposition: domain.DispositionBenign, CaseImpact: domain.ImpactNoneFound},
	}
	for _, d := range ok {
		if err := d.Validate(); err != nil {
			t.Errorf("%s: %v", d.Kind, err)
		}
	}
	bad := map[string]domain.Draft{
		"fact without evidence":      {Kind: domain.KindFact, Text: "f", Basis: domain.BasisObserved},
		"fact as hypothesis":         {Kind: domain.KindFact, Text: "f", Basis: domain.BasisHypothesis, Evidence: ev},
		"hypothesis no confidence":   {Kind: domain.KindHypothesis, Text: "h", Basis: domain.BasisHypothesis},
		"note with evidence":         {Kind: domain.KindNote, Text: "n", Evidence: ev},
		"answer without question":    {Kind: domain.KindAnswer, Text: "a"},
		"unknown evidence kind":      {Kind: domain.KindFact, Text: "f", Basis: domain.BasisObserved, Evidence: []domain.EvidenceRef{{Kind: "x", ID: q}}},
		"link unknown kind":          {Kind: domain.KindLink, Ref: &domain.Ref{Kind: "x", ID: "1"}},
		"close without disposition":  {Kind: domain.KindState, State: domain.StateClosed, CaseImpact: domain.ImpactNoneFound},
		"contain with disposition":   {Kind: domain.KindState, State: domain.StateContained, Disposition: domain.DispositionBenign},
		"no containment no reason":   {Kind: domain.KindState, State: domain.StateContained, NoContainmentNeeded: true},
		"state superseding":          {Kind: domain.KindState, State: domain.StateOpen, Supersedes: &q},
		"owner without owner":        {Kind: domain.KindOwner, OwnerRole: domain.RoleOwner},
		"follow-up without owner":    {Kind: domain.KindOwner, OwnerRole: domain.RoleFollowUp},
		"link supersedes, no reason": {Kind: domain.KindLink, Ref: &domain.Ref{Kind: "run", ID: "1"}, Supersedes: &q},
		"blank text":                 {Kind: domain.KindNote, Text: "  "},
		"long text":                  {Kind: domain.KindNote, Text: strings.Repeat("x", domain.MaxText+1)},
	}
	for name, d := range bad {
		if err := d.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBodyIsCanonicalAndChains(t *testing.T) {
	c, id, q := ids.NewV7(), ids.NewV7(), ids.NewV7()
	d := domain.Draft{Kind: domain.KindAnswer, Text: "yes", Question: &q}
	b, err := d.Body(c, id, 3, author)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"author":{"id":"u1","type":"user"},"case":"` + c.String() + `","id":"` + id.String() +
		`","kind":"ANSWER","question":"` + q.String() + `","seq":3,"text":"yes","v":1}`
	if string(b) != want {
		t.Fatalf("body\n got %s\nwant %s", b, want)
	}
	g := domain.GenesisHash(c)
	if h := sha256.Sum256([]byte("pantherclaw/case/v1/" + c.String())); !bytes.Equal(g, h[:]) {
		t.Fatal("genesis")
	}
	h := sha256.Sum256(append(append([]byte{}, g...), b...))
	if !bytes.Equal(domain.ChainHash(g, b), h[:]) {
		t.Fatal("chain hash")
	}
	if _, err := d.Body(c, id, 0, author); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("seq 0: %v", err)
	}
}

// TestUUIDLinksAreCanonical: a link to an agent, run, transaction, response
// action or ledger entry names a UUID, stored in canonical form (D70).
func TestUUIDLinksAreCanonical(t *testing.T) {
	c, id, agent := ids.NewV7(), ids.NewV7(), ids.NewV7()
	upper := domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: "agent", ID: strings.ToUpper(agent.String())}}
	b, err := upper.Body(c, id, 1, author)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"id":"`+agent.String()+`"`) || strings.Contains(string(b), strings.ToUpper(agent.String())) {
		t.Fatalf("body %s", b)
	}
	for _, kind := range []string{"agent", "run", "transaction", domain.RefResponseAction, "ledger"} {
		d := domain.Draft{Kind: domain.KindLink, Ref: &domain.Ref{Kind: kind, ID: "not-a-uuid"}}
		if err := d.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s link to a non-UUID: %v", kind, err)
		}
	}
}
