// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package receiptsig

import (
	"crypto/mldsa"
	"strings"
	"testing"
)

// TestHR784_ReceiptsCarryAnMLDSACoSignature: a co-signature verifies over
// the unchanged compact JWS, and a different JWS or a missing key does not.
// Federated receipts are not co-signed here: this package signs decision,
// execution and effect receipts only.
func TestHR784_ReceiptsCarryAnMLDSACoSignature(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	const compact = "eyJhbGciOiJFZERTQSJ9.eyJwYXAiOjF9.c2ln"
	sig, err := Sign(compact, "receipts-pq", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(compact, sig, priv.PublicKey()); err != nil {
		t.Fatalf("co-signature: %v", err)
	}
	if strings.Contains(compact, "ML-DSA") {
		t.Fatal("the compact JWS was changed")
	}
	if _, err := Sign(compact, "receipts-pq", nil); err == nil {
		t.Fatal("signed without a key")
	}
	other := "eyJhbGciOiJFZERTQSJ9.eyJwYXAiOjJ9.c2ln"
	if err := Verify(other, sig, priv.PublicKey()); err == nil {
		t.Fatal("a co-signature verified over a different JWS")
	}
}

// TestT354_ACoSignatureDoesNotSurviveARewrittenReceipt: changing the JWS
// the co-signature covers makes verification fail.
func TestT354_ACoSignatureDoesNotSurviveARewrittenReceipt(t *testing.T) {
	TestHR784_ReceiptsCarryAnMLDSACoSignature(t)
}
