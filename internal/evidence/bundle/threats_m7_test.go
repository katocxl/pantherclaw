// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
)

func m7Trust(t *testing.T, iss *bundletest.Issuer) *bundle.Trust {
	t.Helper()
	tr, err := bundle.ParseTrust(iss.Trust())
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// TestT073_ASplitViewIsCaughtByAnotherAuditorsCheckpoint: an insider shows
// two auditors two histories of the same size, both signed with the real
// checkpoints key: the honest one to the first, one with entry 5 rewritten
// to the second. Each view verifies on its own (a signature says who
// signed, not that everyone saw the same tree). Either auditor's saved
// checkpoint, given with the other's bundle (--previous), exposes the
// forked history.
func TestT073_ASplitViewIsCaughtByAnotherAuditorsCheckpoint(t *testing.T) {
	honest := bundletest.NewIssuer(t)
	honest.Append(8)
	savedByFirst := honest.Checkpoint()
	forged := honest.Rewrite(5)
	savedBySecond := forged.Checkpoint()
	trust := m7Trust(t, honest)
	for name, tc := range map[string]struct {
		b        *bundle.Bundle
		previous []byte
	}{
		"the second's view against the first's checkpoint": {forged.Bundle(), savedByFirst},
		"the first's view against the second's checkpoint": {honest.Bundle(), savedBySecond},
	} {
		t.Run(name, func(t *testing.T) {
			if r := bundle.Verify(tc.b, bundle.Options{Trust: trust}); r.Failed() {
				t.Fatalf("a view alone failed, so this shows nothing:\n%s", r.Text())
			}
			r := bundle.Verify(tc.b, bundle.Options{Trust: trust, Previous: tc.previous})
			expect(t, r, "witness.previous", bundle.Failed)
			if !r.Failed() || !strings.Contains(r.Text(), "forked history") {
				t.Fatalf("the split view is not reported as a fork:\n%s", r.Text())
			}
		})
	}
}

// TestT073_ARolledBackHistoryFailsAgainstTheSavedCheckpoint: an auditor
// saved the checkpoint of size 10. The insider then drops entries 8 to 10
// (the incident) and hands over the first seven entries with the real,
// earlier checkpoint of size 7. The bundle verifies on its own, but it
// cannot prove that its history reaches the checkpoint the auditor saved,
// so against it the rollback fails.
func TestT073_ARolledBackHistoryFailsAgainstTheSavedCheckpoint(t *testing.T) {
	iss := bundletest.NewIssuer(t)
	iss.Append(7)
	iss.Checkpoint()
	rolledBack := iss.Bundle()
	iss.Append(3)
	saved := iss.Checkpoint()
	trust := m7Trust(t, iss)

	if r := bundle.Verify(rolledBack, bundle.Options{Trust: trust}); r.Failed() {
		t.Fatalf("the rolled-back bundle alone failed, so this shows nothing:\n%s", r.Text())
	}
	r := bundle.Verify(rolledBack, bundle.Options{Trust: trust, Previous: saved})
	expect(t, r, "witness.previous", bundle.Failed)
	if r.Result == bundle.Passed {
		t.Fatalf("a rolled-back history passed:\n%s", r.Text())
	}
	// The honest bundle, with entries 8 to 10, passes against it.
	if r := bundle.Verify(iss.Bundle(), bundle.Options{Trust: trust, Previous: saved}); r.Failed() {
		t.Fatalf("the honest bundle failed:\n%s", r.Text())
	}
}

// TestT073_ABundleWithItsOwnKeysVerifiesNothing: a forger builds a whole
// deployment of their own for the victim's org (entries, receipts,
// checkpoints, a checkpoint the bundle carries as its own witness, an
// anchor entered in a log and timestamped) and signs all of it with their
// own keys. Against the keys the victim's auditor pinned, nothing the
// forger signed passes, and a bundle that carries keys of its own is not
// even decoded: keys come only from the trust file (HR-196).
func TestT073_ABundleWithItsOwnKeysVerifiesNothing(t *testing.T) {
	victim := bundletest.NewIssuer(t)
	victim.Append(3)
	victim.Checkpoint()
	forger := bundletest.NewIssuer(t)
	forger.Org, forger.Origin = victim.Org, victim.Origin
	forger.Append(5)
	witness := forger.Checkpoint()
	anchored := forger.Anchor(5)
	forger.Append(2)
	forger.Checkpoint()
	fb := forger.Bundle()
	fb.Anchor, fb.Previous = anchored, string(witness)

	sig, err := bundle.ParseSigstoreRoot(victim.SigstoreRoot())
	if err != nil {
		t.Fatal(err)
	}
	r := bundle.Verify(fb, bundle.Options{Trust: m7Trust(t, victim), Sigstore: sig})
	if !r.Failed() || r.Result == bundle.Passed {
		t.Fatalf("a forged deployment passed:\n%s", r.Text())
	}
	// Every signature fails; what rests on a signature (inclusion in a
	// checkpoint, the anchor's log entry and timestamp) never passes. Only
	// unkeyed arithmetic (the chain's hashes, the anchor's tree) can.
	signed := []string{"receipt.signature", "checkpoint.signature", "witness.bundle", "anchor.signature", "anchor.leaf"}
	for _, check := range signed {
		if count(r, check, bundle.Failed) == 0 {
			t.Errorf("%s did not fail:\n%s", check, r.Text())
		}
	}
	for _, check := range append(signed, "checkpoint.consistency", "entry.inclusion", "anchor.log", "anchor.timestamp") {
		if n := count(r, check, bundle.Passed); n != 0 {
			t.Errorf("%s passed %d times for the forger's keys:\n%s", check, n, r.Text())
		}
	}
	// The same bundle carrying the forger's trust file inside it.
	raw := string(bundletest.Encode(t, fb))
	withKeys := strings.Replace(raw, `{"anchor":`, `{"trust":`+string(forger.Trust())+`,"anchor":`, 1)
	if withKeys == raw {
		t.Fatal("the bundle's encoding changed; update the test")
	}
	if _, err := bundle.Decode([]byte(withKeys)); !errors.Is(err, bundle.ErrInvalidBundle) {
		t.Fatalf("a bundle with its own keys decoded: %v", err)
	}
}
