// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package oidcrp

import (
	"context"
	"crypto/fips140"
	"encoding/base64"
	"encoding/json/v2"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func setFIPS(t *testing.T, on bool) {
	t.Helper()
	prev := fipsMode
	fipsMode = func() bool { return on }
	t.Cleanup(func() { fipsMode = prev })
}

// modulus is a base64url modulus of exactly bits bits.
func modulus(bits int) string {
	b := make([]byte, (bits+7)/8)
	for i := range b {
		b[i] = 0x5a
	}
	b[0] = 1 << (bits - (len(b)-1)*8 - 1) // the top bit sits at bit bits-1
	return base64.RawURLEncoding.EncodeToString(b)
}

// TestHR396_SmallIdPRSAKeysAreDroppedFromTheKeySetInFIPSMode: the key set
// a FIPS build uses has no RSA key under 2048 bits; other keys are kept.
func TestHR396_SmallIdPRSAKeysAreDroppedFromTheKeySetInFIPSMode(t *testing.T) {
	set := `{"keys":[` +
		`{"kty":"RSA","kid":"small","e":"AQAB","n":"` + modulus(1024) + `"},` +
		`{"kty":"RSA","kid":"edge","e":"AQAB","n":"` + modulus(2047) + `"},` +
		`{"kty":"RSA","kid":"big","e":"AQAB","n":"` + modulus(2048) + `"},` +
		`{"kty":"EC","kid":"ec","crv":"P-256","x":"AA","y":"AA"},` +
		`{"kty":"RSA","kid":"broken","e":"AQAB","n":"!!"}]}`
	var got struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(dropSmallRSA([]byte(set)), &got); err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range got.Keys {
		kids = append(kids, k.Kid)
	}
	if !slices.Equal(kids, []string{"big", "ec"}) {
		t.Fatalf("kept %v, want [big ec]", kids)
	}
	if string(dropSmallRSA([]byte("not json"))) != "not json" {
		t.Fatal("a body that is not a key set changed")
	}
}

// TestHR396_AnIdPWithA1024BitRSAKeyIsRefusedInFIPSMode: a token signed
// with a 1024-bit RSA key verifies outside FIPS mode and fails in it; one
// signed with a 2048-bit key verifies in both.
func TestHR396_AnIdPWithA1024BitRSAKeyIsRefusedInFIPSMode(t *testing.T) {
	verify := func(t *testing.T, idp *oidctest.Provider) error {
		t.Helper()
		p, err := New(Config{
			Name: "corp", Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
			AllowInsecureLoopback: true, HTTPClient: idp.Client(), SubjectTokenAudience: "https://pc.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		_, err = Subjects{p}.VerifySubject(context.Background(), idp.Token(map[string]any{
			"iss": idp.Issuer(), "sub": "alice", "aud": []string{"https://pc.test"}, "jti": "j",
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		}, ""), false, now)
		return err
	}
	big := oidctest.New(t)
	setFIPS(t, true)
	if err := verify(t, big); err != nil {
		t.Fatalf("a 2048-bit IdP key in FIPS mode: %v", err)
	}
	if fips140.Enabled() {
		t.Skip("a 1024-bit key cannot be generated in a FIPS 140-only process; the key set filter test covers it")
	}
	small := oidctest.NewWithKeyBits(t, 1024)
	if err := verify(t, small); err == nil {
		t.Fatal("a token signed with a 1024-bit RSA key verified in FIPS mode")
	}
	setFIPS(t, false)
	if err := verify(t, small); err != nil {
		t.Fatalf("outside FIPS mode the 1024-bit key is unchanged: %v", err)
	}
}
