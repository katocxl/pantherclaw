// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package proof_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/approvals/proof/prooftest"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	org       = ids.New[ids.Org]().String()
	requested = strings.Repeat("ab", 32)
	effective = strings.Repeat("cd", 32)
	want      = proof.Want{ActionHash: requested, EffectiveHash: effective}
)

func keys(t *testing.T, approvers ...*prooftest.Approver) *proof.Keys {
	t.Helper()
	k, err := proof.ParseFile(prooftest.File(t, org, approvers...))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func refused(t *testing.T, err error, why string) {
	t.Helper()
	if !errors.Is(err, proof.ErrUnverified) {
		t.Fatalf("%s: verified (%v), want refused", why, err)
	}
}

// TestHR038_AGoodAssertionVerifies: an assertion over the binding by a
// pinned key, for the pinned relying party, with user verification,
// verifies for each algorithm a security key may use.
func TestHR038_AGoodAssertionVerifies(t *testing.T) {
	for _, alg := range []webauthntest.Alg{webauthntest.ES256, webauthntest.EdDSA, webauthntest.RS256} {
		bob := prooftest.NewApprover(t, alg)
		b := prooftest.Binding(t, requested, effective)
		if err := keys(t, bob).Verify(prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0)), want); err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
	}
}

// TestHR038_EveryCheckRefuses: a missing file, an unknown key, another
// challenge, no user verification, another relying party, a binding that
// is not its input's hash or names another action, too few approvers, one
// person or key counted twice, and a tampered signature are all refused.
func TestHR038_EveryCheckRefuses(t *testing.T) {
	bob, carol := prooftest.NewApprover(t, webauthntest.ES256), prooftest.NewApprover(t, webauthntest.EdDSA)
	pinned := keys(t, bob, carol)
	b := prooftest.Binding(t, requested, effective)
	good := bob.Assert(t, b.Hash[:], 0)

	var none *proof.Keys
	refused(t, none.Verify(prooftest.Approval(b, good), want), "no keys")
	refused(t, keys(t, carol).Verify(prooftest.Approval(b, good), want), "a key that is not pinned")

	other := prooftest.Binding(t, requested, effective)
	refused(t, pinned.Verify(prooftest.Approval(b, bob.Assert(t, other.Hash[:], 0)), want), "another challenge")

	bob.Key.NoUV = true
	refused(t, pinned.Verify(prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0)), want), "no user verification")
	bob.Key.NoUV = false

	bob.Key.RPID = "evil.example.test"
	refused(t, pinned.Verify(prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0)), want), "another relying party")
	bob.Key.RPID = prooftest.RPID

	a := prooftest.Approval(b, good)
	a.Input = proof.B64(append(bytes.Clone(b.Input), ' '))
	refused(t, pinned.Verify(a, want), "an input that is not the binding's")
	refused(t, pinned.Verify(prooftest.Approval(b, good), proof.Want{ActionHash: effective, EffectiveHash: effective}), "another requested action")
	refused(t, pinned.Verify(prooftest.Approval(b, good), proof.Want{ActionHash: requested, EffectiveHash: requested}), "another effective action")

	two := prooftest.Binding(t, requested, effective, apdomain.Requirement{Kind: apdomain.KindApproval, Role: "approver", Count: 2})
	refused(t, pinned.Verify(prooftest.Approval(two, bob.Assert(t, two.Hash[:], 0)), want), "too few approvers")
	twice := bob.Assert(t, two.Hash[:], 0)
	refused(t, pinned.Verify(prooftest.Approval(two, twice, twice), want), "one key counted twice")
	if err := pinned.Verify(prooftest.Approval(two, bob.Assert(t, two.Hash[:], 0), carol.Assert(t, two.Hash[:], 0)), want); err != nil {
		t.Fatalf("two people with two keys: %v", err)
	}
	// One person with two pinned keys still counts once (HR-035).
	carol.User = bob.User
	refused(t, keys(t, bob, carol).Verify(prooftest.Approval(two, bob.Assert(t, two.Hash[:], 0), carol.Assert(t, two.Hash[:], 0)), want),
		"one person with two keys")
	refused(t, pinned.Verify(prooftest.Approval(b, bob.Assert(t, b.Hash[:], 1)), want), "an assertion toward no requirement")

	tampered := bob.Assert(t, b.Hash[:], 0)
	sig, _ := base64.RawURLEncoding.DecodeString(tampered.Signature)
	sig[len(sig)-1] ^= 1
	tampered.Signature = proof.B64(sig)
	refused(t, pinned.Verify(prooftest.Approval(b, tampered), want), "a tampered signature")
	refused(t, pinned.Verify(prooftest.Approval(b), want), "no assertion")
}

// TestHR038_ABatchAssertionVerifies: an assertion over a batch hash counts
// for an approval in the batch (PAP-1 §8), never for one outside it.
func TestHR038_ABatchAssertionVerifies(t *testing.T) {
	bob := prooftest.NewApprover(t, webauthntest.ES256)
	pinned := keys(t, bob)
	b, c, d := prooftest.Binding(t, requested, effective), prooftest.Binding(t, requested, effective), prooftest.Binding(t, requested, effective)
	batch, err := apdomain.BatchChallenge([][32]byte{b.Hash, c.Hash})
	if err != nil {
		t.Fatal(err)
	}
	as := bob.Assert(t, batch.Hash[:], 0)
	as.Batch = []string{c.String(), b.String()}
	if err := pinned.Verify(prooftest.Approval(b, as), want); err != nil {
		t.Fatalf("a batch approval: %v", err)
	}
	refused(t, pinned.Verify(prooftest.Approval(d, as), want), "an approval outside the batch")
	as.Batch = []string{b.String()}
	refused(t, pinned.Verify(prooftest.Approval(b, as), want), "another batch")
}

// TestHR038_TheFileIsCheckedWhenLoaded: a key whose fingerprint, algorithm
// or encoding is wrong, a credential listed twice, an unknown member, an
// unknown format and another org's file are refused, and a gateway with no
// file or an unreadable one refuses every approval (fail closed).
func TestHR038_TheFileIsCheckedWhenLoaded(t *testing.T) {
	bob := prooftest.NewApprover(t, webauthntest.ES256)
	good := string(prooftest.File(t, org, bob))
	fk := bob.FileKey(t)
	for name, f := range map[string]string{
		"fingerprint": strings.Replace(good, fk.Fingerprint, "sha256:"+strings.Repeat("0", 64), 1),
		"algorithm":   strings.Replace(good, `"algorithm": -7`, `"algorithm": -8`, 1),
		"duplicate":   string(prooftest.File(t, org, bob, bob)),
		"member":      strings.Replace(good, `"format"`, `"role": "admin", "format"`, 1),
		"format":      strings.Replace(good, proof.FileFormat, "pantherclaw.approver-keys/v2", 1),
	} {
		if _, err := proof.ParseFile([]byte(f)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "approver-keys.json")
	b := prooftest.Binding(t, requested, effective)
	a := prooftest.Approval(b, bob.Assert(t, b.Hash[:], 0))
	refused(t, proof.NewPinned("", org).Verify(a, want), "no file configured")
	refused(t, proof.NewPinned(path, org).Verify(a, want), "a missing file")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	refused(t, proof.NewPinned(path, ids.New[ids.Org]().String()).Verify(a, want), "another org's file")
	p := proof.NewPinned(path, org)
	if err := p.Verify(a, want); err != nil {
		t.Fatalf("the installed file: %v", err)
	}
	// A new export replaces the file; the gateway reads it again.
	carol := prooftest.NewApprover(t, webauthntest.ES256)
	if err := os.WriteFile(path, prooftest.File(t, org, carol), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	refused(t, p.Verify(a, want), "a key removed from the file")
}
