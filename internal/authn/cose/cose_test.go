// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cose_test

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/cose"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
)

// TestHR038_StoredKeysConvertToWhatTheGatewayPins: a stored COSE key of
// each allowed algorithm becomes the same DER public key the authenticator
// holds, with its algorithm; anything else is refused.
func TestHR038_StoredKeysConvertToWhatTheGatewayPins(t *testing.T) {
	for _, alg := range []webauthntest.Alg{webauthntest.ES256, webauthntest.EdDSA, webauthntest.RS256} {
		k, err := webauthntest.New("https://localhost", "localhost", alg)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := k.COSEKey()
		if err != nil {
			t.Fatal(err)
		}
		got, der, err := cose.PKIX(stored)
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		want, _ := x509.MarshalPKIXPublicKey(k.PublicKey())
		if got != int(alg) || !bytes.Equal(der, want) {
			t.Fatalf("alg %d: got %d and another key", alg, got)
		}
	}
	if _, _, err := cose.PKIX([]byte{0xa0}); err == nil {
		t.Fatal("an empty COSE map converted")
	}
}
