// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var update = flag.Bool("update", false, "rewrite golden files")

func hexOf(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), 32) }

func approver(count int, independent bool) domain.Requirement {
	return domain.Requirement{
		Kind: domain.KindApproval, Role: "approver", Count: count, Independent: independent,
		Sources: []domain.Source{{Level: "policy p@1 rule refunds-over-50", Reason: "REFUND_OVER_50"}},
	}
}

// parts is a fixed, realistic action binding input.
func parts() domain.ActionParts {
	return domain.ActionParts{
		ActionHash:          hexOf(0x11),
		EffectiveActionHash: hexOf(0x11),
		BasisDigest:         "sha256:" + hexOf(0x22),
		FactsDigest:         "sha256:" + hexOf(0x33),
		DefinitionDigest:    "sha256:" + hexOf(0x44),
		GrantID:             uid("0192f3a0-0000-7000-8000-000000000001"),
		GrantRevision:       2,
		RunID:               uid("0192f3a0-0000-7000-8000-000000000002"),
		Instance:            uid("0192f3a0-0000-7000-8000-000000000003"),
		JKT:                 "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
		Requirements:        []domain.Requirement{approver(1, false)},
		ExpiresAt:           time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC),
		DisplayHash:         sha256.Sum256([]byte(`{"title":"Refund ch_1"}`)),
	}
}

type vector struct {
	Name    string `json:"name"`
	Input   string `json:"input"`
	Binding string `json:"binding"`
}

func vectors(t *testing.T) []vector {
	t.Helper()
	two := parts()
	two.Requirements = []domain.Requirement{
		approver(2, true),
		{Kind: domain.KindStepUp, Subject: domain.SubjectPrincipal, Method: domain.MethodWebAuthn},
	}
	clamped := parts()
	clamped.EffectiveActionHash = hexOf(0x55)
	restore := domain.RestorationParts{
		AgentID: uid("0192f3a0-0000-7000-8000-000000000004"), ChangeSeq: 7,
		RequestedState: "PROTECTED", RequestedBy: uid("0192f3a0-0000-7000-8000-000000000005"),
		Reason: "incident 42 closed", Requirements: []domain.Requirement{approver(1, false)},
		ExpiresAt: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC), DisplayHash: sha256.Sum256([]byte(`{}`)),
	}
	var out []vector
	for _, c := range []struct {
		name string
		b    func() (domain.Binding, error)
	}{
		{"one approver", parts().Binding},
		{"two independent approvers and a principal step-up", two.Binding},
		{"an obligation clamps the action", clamped.Binding},
		{"a restoration", restore.Binding},
	} {
		b, err := c.b()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		out = append(out, vector{Name: c.name, Input: string(b.Input), Binding: b.String()})
	}
	b1, _ := parts().Binding()
	b2, _ := two.Binding()
	batch, err := domain.BatchChallenge([][32]byte{b2.Hash, b1.Hash})
	if err != nil {
		t.Fatal(err)
	}
	return append(out, vector{Name: "a batch of two", Input: string(batch.Input), Binding: batch.String()})
}

// TestHR030_BindingGoldenVectors: the binding is SHA-256 over the RFC 8785
// canonical JSON of exactly the PAP-1 §8 fields; these vectors pin it, so
// any change to the encoding is a protocol change.
func TestHR030_BindingGoldenVectors(t *testing.T) {
	got := vectors(t)
	path := filepath.Join("testdata", "binding_vectors.json")
	if *update {
		raw, err := json.Marshal(got, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		buf.Write(raw)
		buf.WriteByte('\n')
		if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want []vector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(want) != len(got) {
		t.Fatalf("%d vectors, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s:\n got %s %s\nwant %s %s", want[i].Name, got[i].Binding, got[i].Input, want[i].Binding, want[i].Input)
		}
		sum := sha256.Sum256([]byte(want[i].Input))
		if domain.B64(sum[:]) != want[i].Binding {
			t.Errorf("%s: the binding is not the SHA-256 of its input", want[i].Name)
		}
	}
	// The canonical form sorts keys, has no whitespace and writes hashes as
	// base64url and the expiry in whole seconds UTC.
	first := want[0].Input
	for _, s := range []string{
		`{"action_hash":"ERERERERERERERERERERERERERERERERERERERERERE",`,
		`"approver_requirements":[{"count":1,"kind":"approval","role":"approver"}]`,
		`"expires_at":"2026-10-10T12:00:00Z"`,
		`"grant":{"id":"0192f3a0-0000-7000-8000-000000000001","revision":2}`,
		`"v":1}`,
	} {
		if !strings.Contains(first, s) {
			t.Errorf("canonical input lacks %s:\n%s", s, first)
		}
	}
}

// TestHR030_AnyInputChangesTheBinding: changing any one input gives a
// different binding (property test over every field).
func TestHR030_AnyInputChangesTheBinding(t *testing.T) {
	base, err := parts().Binding()
	if err != nil {
		t.Fatal(err)
	}
	other := ids.NewV7()
	mutations := []func(p *domain.ActionParts, b byte){
		func(p *domain.ActionParts, b byte) { p.ActionHash = hexOf(b) },
		func(p *domain.ActionParts, b byte) { p.EffectiveActionHash = hexOf(b) },
		func(p *domain.ActionParts, b byte) { p.BasisDigest = hexOf(b) },
		func(p *domain.ActionParts, b byte) { p.FactsDigest = hexOf(b) },
		func(p *domain.ActionParts, b byte) { p.DefinitionDigest = hexOf(b) },
		func(p *domain.ActionParts, b byte) { p.GrantID = other },
		func(p *domain.ActionParts, b byte) { p.GrantRevision += int(b) + 1 },
		func(p *domain.ActionParts, b byte) { p.RunID = other },
		func(p *domain.ActionParts, b byte) { p.Instance = other },
		func(p *domain.ActionParts, b byte) { p.JKT = string(rune('A'+b%13)) + p.JKT[1:] },
		func(p *domain.ActionParts, b byte) { p.Requirements = []domain.Requirement{approver(2, false)} },
		func(p *domain.ActionParts, b byte) { p.Requirements = []domain.Requirement{approver(1, true)} },
		func(p *domain.ActionParts, b byte) {
			p.ExpiresAt = p.ExpiresAt.Add(time.Duration(int(b)+1) * time.Second)
		},
		func(p *domain.ActionParts, b byte) { p.DisplayHash[b%32] ^= 1 },
	}
	rapid.Check(t, func(rt *rapid.T) {
		i := rapid.IntRange(0, len(mutations)-1).Draw(rt, "field")
		b := rapid.ByteRange(0, 0x10).Draw(rt, "value") // never 0x11, the base action hash
		p := parts()
		mutations[i](&p, b)
		got, err := p.Binding()
		if err != nil {
			rt.Fatalf("mutation %d: %v", i, err)
		}
		if got.Hash == base.Hash {
			rt.Fatalf("mutation %d did not change the binding", i)
		}
	})
}

// TestHR030_SiblingRunOrOtherInstanceOrKeyNeverMatches (T-005): the same
// action hash under another run, instance or key is another binding, so an
// approval cannot be stolen by a sibling run or replayed by another key.
func TestHR030_SiblingRunOrOtherInstanceOrKeyNeverMatches(t *testing.T) {
	base, _ := parts().Binding()
	for name, change := range map[string]func(*domain.ActionParts){
		"sibling run":    func(p *domain.ActionParts) { p.RunID = ids.NewV7() },
		"other instance": func(p *domain.ActionParts) { p.Instance = ids.NewV7() },
		"other key":      func(p *domain.ActionParts) { p.JKT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
	} {
		p := parts()
		change(&p)
		got, err := p.Binding()
		if err != nil || got.Hash == base.Hash {
			t.Errorf("%s: binding %s, %v; must differ", name, got, err)
		}
	}
}

func TestBindingAcceptsEveryHashSpellingAndRefusesIncompleteInputs(t *testing.T) {
	base, _ := parts().Binding()
	p := parts()
	raw, _ := hex.DecodeString(hexOf(0x11))
	p.ActionHash, p.EffectiveActionHash = "sha256:"+hexOf(0x11), domain.B64(raw)
	if got, err := p.Binding(); err != nil || got.Hash != base.Hash {
		t.Fatalf("hex, prefixed hex and base64url spell one hash: %s, %v", got, err)
	}
	for name, change := range map[string]func(*domain.ActionParts){
		"a short hash":               func(p *domain.ActionParts) { p.ActionHash = "abcd" },
		"no grant revision":          func(p *domain.ActionParts) { p.GrantRevision = 0 },
		"no run":                     func(p *domain.ActionParts) { p.RunID = ids.UUID{} },
		"no key":                     func(p *domain.ActionParts) { p.JKT = "" },
		"no requirements":            func(p *domain.ActionParts) { p.Requirements = nil },
		"an expiry in fractions":     func(p *domain.ActionParts) { p.ExpiresAt = p.ExpiresAt.Add(time.Millisecond) },
		"no expiry":                  func(p *domain.ActionParts) { p.ExpiresAt = time.Time{} },
		"a definition digest in hex": func(p *domain.ActionParts) { p.DefinitionDigest = "sha256:xyz" },
	} {
		q := parts()
		change(&q)
		if _, err := q.Binding(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Sources explain a requirement but are not bound: they are in the basis.
	q := parts()
	q.Requirements[0].Sources = []domain.Source{{Level: "grant g r9", Reason: "OTHER"}}
	if got, _ := q.Binding(); got.Hash != base.Hash {
		t.Error("a requirement's sources changed the binding")
	}
}

// TestHR175_BatchChallengeCoversExactlyItsBindings: the batch hash is over
// the sorted bindings, in any order, and changes with any member.
func TestHR175_BatchChallengeCoversExactlyItsBindings(t *testing.T) {
	a, b, c := [32]byte{1}, [32]byte{2}, [32]byte{3}
	ab, _ := domain.BatchChallenge([][32]byte{a, b})
	ba, _ := domain.BatchChallenge([][32]byte{b, a})
	abc, _ := domain.BatchChallenge([][32]byte{a, b, c})
	if ab.Hash != ba.Hash || ab.Hash == abc.Hash {
		t.Fatal("the batch challenge depends on order or ignores a member")
	}
	if _, err := domain.BatchChallenge([][32]byte{a, a}); err == nil {
		t.Fatal("a batch naming one request twice was accepted")
	}
	if _, err := domain.BatchChallenge(nil); err == nil {
		t.Fatal("an empty batch was accepted")
	}
}

func TestVariantKeyGroupsGrantOperationAndTarget(t *testing.T) {
	g := ids.NewV7()
	k := func(g ids.UUID, op, id string) [32]byte {
		v, err := domain.VariantKey(g, op, domain.Target{Type: "payments.charge", ID: id})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	first, again := k(g, "payments.refund.create", "ch_1"), k(g, "payments.refund.create", "ch_1")
	if first != again {
		t.Fatal("variant key is not deterministic")
	}
	if first == k(g, "payments.refund.create", "ch_2") || first == k(ids.NewV7(), "payments.refund.create", "ch_1") ||
		first == k(g, "payments.charge.capture", "ch_1") {
		t.Fatal("variant key merges different grants, operations or targets")
	}
	if _, err := domain.VariantKey(g, "", domain.Target{Type: "x", ID: "y"}); err == nil {
		t.Fatal("a variant key without an operation was accepted")
	}
}

func uid(s string) ids.UUID {
	u, err := ids.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

// TestHR030_ConditionLimitsChangeTheBinding: the binding covers the
// display, so a display that differs only in its condition limits (F159)
// gives another display hash and another binding, and a stored version 2
// display, read back, still hashes to the display hash it was bound with.
//
// Covers: F159
func TestHR030_ConditionLimitsChangeTheBinding(t *testing.T) {
	disp := domain.Display{V: domain.DisplayVersion, Kind: "action", Title: "Refund ch_1"}
	limited := disp
	limited.Consequence.ConditionLimits = []string{domain.NoVerifierLimit}
	bindingOf := func(d domain.Display) domain.Binding {
		t.Helper()
		c, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		p := parts()
		p.DisplayHash = c.Hash
		b, err := p.Binding()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if bindingOf(disp).Hash == bindingOf(limited).Hash {
		t.Fatal("the condition limits do not change the binding")
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "display_v2_mock_payments.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		Display     jsontext.Value `json:"display"`
		DisplayHash string         `json:"display_hash"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	var v2 domain.Display
	if err := json.Unmarshal(stored.Display, &v2); err != nil {
		t.Fatal(err)
	}
	c, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if v2.V != 2 || c.String() != stored.DisplayHash || !bytes.Equal(c.Input, stored.Display) {
		t.Fatalf("a stored v2 display reads back as v%d with hash %s, want %s", v2.V, c.String(), stored.DisplayHash)
	}
}
