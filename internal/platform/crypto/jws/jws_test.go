// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package jws

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

const testTyp = "pap-permit+jwt"

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// forge builds a compact JWS from a raw header, signing with priv (Ed25519).
func forge(priv ed25519.PrivateKey, headerJSON, payload string) string {
	input := b64(headerJSON) + "." + b64(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
}

func setup(t *testing.T) (*Signer, *Verifier, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := newKey(t)
	s, err := NewSigner("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(testTyp, map[string]ed25519.PublicKey{"k1": pub})
	if err != nil {
		t.Fatal(err)
	}
	return s, v, priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s, v, _ := setup(t)
	tok, err := s.Sign(testTyp, []byte(`{"jti":"p1"}`))
	if err != nil {
		t.Fatal(err)
	}
	payload, kid, err := v.Verify(tok)
	if err != nil || string(payload) != `{"jti":"p1"}` || kid != "k1" {
		t.Fatalf("Verify = %q, %q, %v", payload, kid, err)
	}
	if k, typ, err := Unverified(tok); err != nil || k != "k1" || typ != testTyp {
		t.Fatalf("Unverified = %q %q %v", k, typ, err)
	}
	if !s.Public().Equal(v.keys["k1"]) {
		t.Fatal("Public() does not match")
	}
}

func TestHR095_RejectsAlgNoneAndHMACConfusion(t *testing.T) {
	_, v, _ := setup(t)
	pub := v.keys["k1"]
	none := b64(`{"alg":"none","kid":"k1","typ":"`+testTyp+`"}`) + "." + b64(`{}`) + "."
	// HS256 "signed" with the Ed25519 public key as the HMAC secret.
	input := b64(`{"alg":"HS256","kid":"k1","typ":"`+testTyp+`"}`) + "." + b64(`{}`)
	m := hmac.New(sha256.New, pub)
	m.Write([]byte(input))
	hs := input + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	for name, tok := range map[string]string{"none": none, "HS256 confusion": hs} {
		if _, _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestHR095_RejectsUntrustedHeaderMembers(t *testing.T) {
	_, v, priv := setup(t)
	attacker, attackerPriv := newKey(t)
	jwk := `{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(attacker) + `"}`
	cases := map[string]string{
		// Signed by the attacker's key, which is embedded in the token.
		"embedded jwk": forge(attackerPriv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`","jwk":`+jwk+`}`, `{}`),
		// Correctly signed by the real key but carrying extra headers.
		"jku":          forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`","jku":"https://evil.example/jwks"}`, `{}`),
		"x5u":          forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`","x5u":"https://evil.example/c"}`, `{}`),
		"crit b64":     forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`","crit":["b64"],"b64":false}`, `{}`),
		"zip":          forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`","zip":"DEF"}`, `{}`),
		"duplicate":    forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`","typ":"other"}`, `{}`),
		"wrong typ":    forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"pap-decision+jwt"}`, `{}`),
		"missing typ":  forge(priv, `{"alg":"EdDSA","kid":"k1"}`, `{}`),
		"unknown kid":  forge(priv, `{"alg":"EdDSA","kid":"k2","typ":"`+testTyp+`"}`, `{}`),
		"missing kid":  forge(priv, `{"alg":"EdDSA","typ":"`+testTyp+`"}`, `{}`),
		"ES256":        forge(priv, `{"alg":"ES256","kid":"k1","typ":"`+testTyp+`"}`, `{}`),
		"attacker key": forge(attackerPriv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`"}`, `{}`),
	}
	for name, tok := range cases {
		if _, _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (err %v)", name, err)
		}
	}
	// Sanity: the forge helper produces valid tokens when nothing is wrong.
	if _, _, err := v.Verify(forge(priv, `{"alg":"EdDSA","kid":"k1","typ":"`+testTyp+`"}`, `{}`)); err != nil {
		t.Fatalf("well-formed forged token rejected: %v", err)
	}
}

func TestRejectsTamperingAndMalformedInput(t *testing.T) {
	s, v, _ := setup(t)
	tok, _ := s.Sign(testTyp, []byte(`{"amount":"30.00"}`))
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + b64(`{"amount":"300.00"}`) + "." + parts[2]
	for name, bad := range map[string]string{
		"tampered payload": tampered,
		"whitespace":       tok[:10] + "\n" + tok[10:],
		"two segments":     parts[0] + "." + parts[1],
		"four segments":    tok + ".x",
		"padded header":    parts[0] + "=." + parts[1] + "." + parts[2],
		"oversized":        strings.Repeat("a", MaxCompactBytes+1),
		"empty":            "",
		"JSON form":        `{"payload":"e30","signatures":[]}`,
	} {
		if _, _, err := v.Verify(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (err %v)", name, err)
		}
	}
}

func TestConstructorValidation(t *testing.T) {
	_, priv := newKey(t)
	if _, err := NewSigner("", priv); err == nil {
		t.Error("empty kid accepted")
	}
	if _, err := NewSigner("k", priv[:10]); err == nil {
		t.Error("short private key accepted")
	}
	if _, err := NewVerifier("", nil); err == nil {
		t.Error("empty typ accepted")
	}
	if _, err := NewVerifier("t", map[string]ed25519.PublicKey{"k": make([]byte, 5)}); err == nil {
		t.Error("short public key accepted")
	}
	s, _ := NewSigner("k", priv)
	if _, err := s.Sign("", nil); err == nil {
		t.Error("empty typ accepted by Sign")
	}
}

// malleate changes the unused low bits of the token's last base64
// character, which base64 decoders ignore: the result decodes to the same
// bytes.
func malleate(t *testing.T, tok string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	sig := tok[strings.LastIndexByte(tok, '.')+1:]
	if len(sig)%4 < 2 {
		t.Fatalf("the last segment has no unused bits (%d characters)", len(sig))
	}
	i := strings.IndexByte(alphabet, tok[len(tok)-1])
	return tok[:len(tok)-1] + string(alphabet[i^1])
}

// TestNonCanonicalEncodingsAreOneToken: a signature whose last character
// differs only in unused bits decodes to the same bytes. Canonical maps it
// back to the original, and Verify refuses it, so one token has one string
// (HR-143, HR-145).
func TestNonCanonicalEncodingsAreOneToken(t *testing.T) {
	s, v, priv := setup(t)
	tok, _ := s.Sign(testTyp, []byte(`{"amount":"30.00"}`))
	odd := malleate(t, tok)
	if odd == tok {
		t.Fatal("malleate changed nothing")
	}
	sig := func(x string) string {
		raw, err := base64.RawURLEncoding.DecodeString(x[strings.LastIndexByte(x, '.')+1:])
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if sig(odd) != sig(tok) {
		t.Fatal("the variant decodes to another signature")
	}
	// The premise: go-jose alone verifies the variant.
	if obj, err := jose.ParseSignedCompact(odd, allowed); err != nil {
		t.Fatalf("go-jose refused the variant: %v", err)
	} else if _, err := obj.Verify(priv.Public()); err != nil {
		t.Fatalf("go-jose refused the variant's signature: %v", err)
	}
	if c, ok := Canonical(odd); !ok || c != tok {
		t.Fatalf("Canonical(variant) = %q, %v; want the original", c, ok)
	}
	if c, ok := Canonical(tok); !ok || c != tok {
		t.Fatalf("Canonical(original) = %q, %v", c, ok)
	}
	if _, _, err := v.Verify(tok); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Verify(odd); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical variant accepted (err %v)", err)
	}
	for _, bad := range []string{"", "a.b", "a.b.c.d", "a.b.!!"} {
		if _, ok := Canonical(bad); ok {
			t.Errorf("Canonical(%q) ok", bad)
		}
	}
}
