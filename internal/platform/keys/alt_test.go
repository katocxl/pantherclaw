// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR095_EachEvidencePurposeHasOneAlgorithm: anchors is ES256,
// checkpoints_pq is ML-DSA-65, every other purpose EdDSA (G0 M7 design
// decision 17), and keys of one algorithm never stand in for another.
func TestHR095_EachEvidencePurposeHasOneAlgorithm(t *testing.T) {
	for _, p := range Purposes() {
		if p.Algorithm() != AlgEdDSA {
			t.Errorf("%s: %s, want EdDSA", p, p.Algorithm())
		}
	}
	if PurposeAnchors.Algorithm() != AlgES256 || PurposeCheckpointsPQ.Algorithm() != AlgMLDSA65 {
		t.Fatal("anchors must be ES256 and checkpoints_pq ML-DSA-65")
	}
	for _, p := range EvidencePurposes() {
		if !p.Valid() {
			t.Errorf("evidence purpose %s is not valid", p)
		}
	}
	for _, p := range AltPurposes() {
		if _, err := GenerateSigningKey(p); err == nil {
			t.Errorf("an Ed25519 key was generated for %s", p)
		}
	}
	if _, _, err := GenerateAltKey(PurposeCheckpoints); err == nil {
		t.Error("an alternative-algorithm key was generated for checkpoints")
	}
	ed, err := GenerateSigningKey(PurposeCheckpoints)
	if err != nil {
		t.Fatal(err)
	}
	ed.Purpose = PurposeAnchors
	if err := NewRegistry().Put(ed); err == nil {
		t.Error("an Ed25519 key was registered as an anchors key")
	}
}

func TestAltKeysRoundTripAndRegister(t *testing.T) {
	for _, tc := range []struct {
		purpose Purpose
		size    int
	}{{PurposeAnchors, 91}, {PurposeCheckpointsPQ, mldsa.MLDSA65PublicKeySize}} {
		t.Run(string(tc.purpose), func(t *testing.T) {
			k, private, err := GenerateAltKey(tc.purpose)
			if err != nil {
				t.Fatal(err)
			}
			wantPrefix := strings.ReplaceAll(string(tc.purpose), "_", "-") + "-"
			if len(k.Public) != tc.size || !strings.HasPrefix(k.KID, wantPrefix) || k.KID != AltKIDFor(tc.purpose, k.Public) {
				t.Fatalf("key %s with a %d-byte public key", k.KID, len(k.Public))
			}
			if len(private.Reveal()) != 32 {
				t.Fatalf("private encoding is %d bytes, want 32", len(private.Reveal()))
			}
			opened, err := OpenAltKey(tc.purpose, k.KID, k.Public, private.Reveal())
			if err != nil {
				t.Fatal(err)
			}
			other, _, _ := GenerateAltKey(tc.purpose)
			if _, err := OpenAltKey(tc.purpose, other.KID, other.Public, private.Reveal()); err == nil {
				t.Error("a private key opened against another public key")
			}
			reg := NewRegistry()
			if err := reg.PutAlt(opened); err != nil {
				t.Fatal(err)
			}
			if err := reg.PutAlt(other); err == nil {
				t.Error("a second active key of one purpose was accepted")
			}
			other.State, other.Private = StateRetiring, pclog.Secret[crypto.Signer]{}
			if err := reg.PutAlt(other); err != nil {
				t.Fatal(err)
			}
			got := reg.AltKeys(tc.purpose)
			if len(got) != 2 || got[0].KID != k.KID || got[0].State != StateActive {
				t.Fatalf("AltKeys = %+v, want the active key first", got)
			}
			bad := opened
			bad.Private = pclog.Secret[crypto.Signer]{}
			if err := NewRegistry().PutAlt(bad); err == nil {
				t.Error("an active key without its private half was accepted")
			}
			bad = opened
			bad.KID = AltKIDFor(tc.purpose, other.Public)
			if err := NewRegistry().PutAlt(bad); err == nil {
				t.Error("a key under another key's kid was accepted")
			}
		})
	}
}

// TestAltKeysSign: the anchors key signs ECDSA P-256 over SHA-256 and the
// checkpoints_pq key signs ML-DSA-65; both verify with their published key.
func TestAltKeysSign(t *testing.T) {
	a, _, err := GenerateAltKey(PurposeAnchors)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("statement"))
	sig, err := a.Private.Reveal().Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.ParsePKIXPublicKey(a.Public)
	if err != nil || !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("the anchors signature does not verify with the published key")
	}
	q, _, err := GenerateAltKey(PurposeCheckpointsPQ)
	if err != nil {
		t.Fatal(err)
	}
	opts := &mldsa.Options{Context: "test"}
	sig, err = q.Private.Reveal().Sign(rand.Reader, []byte("note"), opts)
	if err != nil {
		t.Fatal(err)
	}
	qpub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), q.Public)
	if err != nil || mldsa.Verify(qpub, []byte("note"), sig, opts) != nil {
		t.Fatal("the ML-DSA-65 signature does not verify with the published key")
	}
}
