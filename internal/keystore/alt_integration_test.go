// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package keystore_test

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// TestHR095_EvidenceKeysAreCreatedWithTheirAlgorithms: the anchors key is
// always an ECDSA P-256 key; the ML-DSA-65 checkpoints_pq key exists only
// once it is asked for (evidence.mldsa_cosign), and both reload with their
// private halves after a restart (G0 M7 design decisions 6 and 17).
func TestHR095_EvidenceKeysAreCreatedWithTheirAlgorithms(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	anchors := reg.AltKeys(keys.PurposeAnchors)
	if len(anchors) != 1 || anchors[0].State != keys.StateActive || anchors[0].Private.Reveal() == nil {
		t.Fatalf("anchors keys = %+v, want one active key with its private half", anchors)
	}
	if n := platformCount(t, p, "SELECT count(*) FROM pc.keys WHERE purpose = 'anchors' AND algorithm = 'ES256'"); n != 1 {
		t.Fatalf("ES256 anchors keys = %d, want 1", n)
	}
	if got := reg.AltKeys(keys.PurposeCheckpointsPQ); len(got) != 0 {
		t.Fatalf("an ML-DSA-65 key exists without evidence.mldsa_cosign: %+v", got)
	}

	if err := keystore.LoadSigningKeys(ctx, p, kp, keys.NewRegistry(), keys.PurposeCheckpointsPQ); err != nil {
		t.Fatal(err)
	}
	reg = keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	pq := reg.AltKeys(keys.PurposeCheckpointsPQ)
	if len(pq) != 1 || pq[0].Private.Reveal() == nil {
		t.Fatalf("checkpoints_pq keys after a restart = %+v, want the active key", pq)
	}
	if reg.AltKeys(keys.PurposeAnchors)[0].KID != anchors[0].KID {
		t.Fatal("a restart created a new anchors key")
	}
	opts := &mldsa.Options{Context: "test"}
	sig, err := pq[0].Private.Reveal().Sign(rand.Reader, []byte("note"), opts)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pq[0].Public)
	if err != nil || mldsa.Verify(pub, []byte("note"), sig, opts) != nil {
		t.Fatal("the reloaded ML-DSA-65 key does not sign for its stored public key")
	}
	if n := platformCount(t, p, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.signing_key.created'"); n != len(keys.Purposes())+2 {
		t.Fatalf("audit entries = %d, want one per created key", n)
	}
}

// TestHR062_AlternativeKeysCannotBeSwappedBetweenRows: the wrap of an
// ES256 key is bound to its row like an Ed25519 key's.
func TestHR062_AlternativeKeysCannotBeSwappedBetweenRows(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	if err := keystore.LoadSigningKeys(ctx, p, kp, keys.NewRegistry()); err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, `UPDATE pc.keys k SET wrapped_private_key = r.wrapped_private_key
		FROM pc.keys r WHERE k.purpose = 'anchors' AND r.purpose = 'receipts' AND k.org_id = r.org_id`)
	if err := keystore.LoadSigningKeys(ctx, p, kp, keys.NewRegistry()); !errors.Is(err, keys.ErrUnwrap) {
		t.Fatalf("swapped wrapped key accepted: %v", err)
	}
}

func TestIntAnchorsKeyRotates(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	kp := provider(t)
	ctx := context.Background()
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	old := reg.AltKeys(keys.PurposeAnchors)[0].KID
	kid, err := keystore.RotateSigningKey(ctx, p, kp, keys.PurposeAnchors, domain.Actor{Type: "user", ID: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	reg = keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, p, kp, reg); err != nil {
		t.Fatal(err)
	}
	got := reg.AltKeys(keys.PurposeAnchors)
	if len(got) != 2 || got[0].KID != kid || got[1].KID != old || got[1].State != keys.StateRetiring || got[1].Private.Reveal() != nil {
		t.Fatalf("after rotation = %+v, want the new key active and the old one retiring without its private half", got)
	}
	published, err := keystore.PublishedKeys(ctx, p, []keys.Purpose{keys.PurposeAnchors})
	if err != nil || len(published) != 2 || published[0].KID != old || published[0].Algorithm != keys.AlgES256 ||
		!published[0].Changed.After(published[0].Created) {
		t.Fatalf("published anchors keys = %+v, %v", published, err)
	}
}
