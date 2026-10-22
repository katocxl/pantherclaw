// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSHA256KnownAnswer(t *testing.T) {
	got := hex.EncodeToString(SHA256([]byte("abc")))
	if got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("SHA256(abc) = %s", got)
	}
	if HashB64([]byte("abc")) != "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0" {
		t.Fatalf("HashB64(abc) = %s", HashB64([]byte("abc")))
	}
}

func TestHMACSHA256KnownAnswer(t *testing.T) {
	// RFC 4231 test case 1 (a 160-bit key, valid in FIPS 140-only mode).
	got := hex.EncodeToString(HMACSHA256(bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There")))
	if got != "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" {
		t.Fatalf("HMAC = %s", got)
	}
	if fips140.Enabled() {
		return // test case 2's 32-bit key is refused in FIPS 140-only mode
	}
	// RFC 4231 test case 2.
	got = hex.EncodeToString(HMACSHA256([]byte("Jefe"), []byte("what do ya want for nothing?")))
	if got != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Fatalf("HMAC = %s", got)
	}
}

func TestB64Strict(t *testing.T) {
	b, err := FromB64("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0")
	if err != nil || len(b) != 32 {
		t.Fatalf("FromB64 = %d bytes, %v", len(b), err)
	}
	for _, s := range []string{"YWJj=", "ab+/", "YW Jj"} {
		if _, err := FromB64(s); err == nil {
			t.Errorf("FromB64(%q) accepted non-canonical input", s)
		}
	}
}

func TestEqualConstantTimeSemantics(t *testing.T) {
	if !Equal([]byte("abc"), []byte("abc")) || Equal([]byte("abc"), []byte("abd")) || Equal([]byte("abc"), []byte("ab")) {
		t.Fatal("Equal is wrong")
	}
}

func TestAESGCMKnownAnswer(t *testing.T) {
	// McGrew & Viega GCM spec, test case 14 (AES-256, zero key/IV, one zero block).
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	pt := make([]byte, 16)
	want := mustHex(t, "cea7403d4d606b6e074ec5d3baf39d18"+"d0d1c8a799996bf0265b98b5d48ab919")
	// FIPS 140-only mode refuses GCM with caller-chosen nonces, so the
	// reference cross-check runs outside it; the vector check below runs in
	// both.
	if !fips140.Enabled() {
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		if got := gcm.Seal(nil, nonce, pt, nil); !bytes.Equal(got, want) {
			t.Fatalf("reference GCM = %x, want %x", got, want)
		}
	}
	// Our AEAD's wire format is nonce ‖ ciphertext ‖ tag: it must open the vector.
	a, err := NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Open(append(append([]byte{}, nonce...), want...), nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("Open(KAT) = %x, %v", got, err)
	}
}

func TestAEADRoundTripAndTamper(t *testing.T) {
	a, err := NewAEAD(NewKey())
	if err != nil {
		t.Fatal(err)
	}
	ct := a.Seal([]byte("hello"), []byte("ctx"))
	ct2 := a.Seal([]byte("hello"), []byte("ctx"))
	if bytes.Equal(ct, ct2) {
		t.Fatal("two encryptions are identical: nonce reuse")
	}
	if pt, err := a.Open(ct, []byte("ctx")); err != nil || string(pt) != "hello" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	for i := range ct {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if _, err := a.Open(bad, []byte("ctx")); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipping byte %d was not detected", i)
		}
	}
	if _, err := a.Open(ct, []byte("ctx2")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong AAD accepted")
	}
	if _, err := a.Open(ct[:10], nil); !errors.Is(err, ErrDecrypt) {
		t.Fatal("short ciphertext accepted")
	}
	if _, err := NewAEAD(make([]byte, 16)); err == nil {
		t.Fatal("AES-128 key accepted; only AES-256 is allowed")
	}
}

func TestAADIsInjective(t *testing.T) {
	a, _ := NewAAD("l").Str("ab").Str("c").Build()
	b, _ := NewAAD("l").Str("a").Str("bc").Build()
	if bytes.Equal(a, b) {
		t.Fatal("length prefixes missing: (ab,c) == (a,bc)")
	}
	if _, err := NewAAD("l").Str("").Build(); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("empty field accepted")
	}
	if _, err := NewAAD("l").Str(string(make([]byte, 256))).Build(); !errors.Is(err, ErrInvalidContext) {
		t.Fatal("oversized field accepted")
	}
}

// memDEKs is an in-memory DEKSource for tests.
type memDEKs struct {
	current uint32
	keys    map[string][]byte // "org|purpose|version" → key
}

func newMemDEKs() *memDEKs { return &memDEKs{current: 1, keys: map[string][]byte{}} }

func (m *memDEKs) id(org ids.OrgID, purpose string, v uint32) string {
	return fmt.Sprintf("%s|%s|%d", org, purpose, v)
}

func (m *memDEKs) CurrentDEK(_ context.Context, org ids.OrgID, purpose string) (uint32, pclog.Secret[[]byte], error) {
	k, ok := m.keys[m.id(org, purpose, m.current)]
	if !ok {
		k = NewKey()
		m.keys[m.id(org, purpose, m.current)] = k
	}
	return m.current, pclog.NewSecret(k), nil
}

func (m *memDEKs) DEK(_ context.Context, org ids.OrgID, purpose string, v uint32) (pclog.Secret[[]byte], error) {
	k, ok := m.keys[m.id(org, purpose, v)]
	if !ok {
		return pclog.Secret[[]byte]{}, ErrUnknownDEK
	}
	return pclog.NewSecret(k), nil
}

func TestHR062_EnvelopeBindsOrgTableColumnRow(t *testing.T) {
	ctx := context.Background()
	deks := newMemDEKs()
	env := NewEnvelope(deks)
	orgA, orgB := ids.New[ids.Org](), ids.New[ids.Org]()
	home := FieldContext{Org: orgA, Table: "connections", Column: "sealed_credential", RowID: "row-1"}
	blob, err := env.Encrypt(ctx, home, "credentials", []byte("sk_live_not_real"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := env.Decrypt(ctx, home, "credentials", blob); err != nil || string(pt) != "sk_live_not_real" {
		t.Fatalf("Decrypt(home) = %q, %v", pt, err)
	}
	// Give org B a DEK too, so the org swap fails on AAD and not just on a
	// missing key.
	if _, _, err := deks.CurrentDEK(ctx, orgB, "credentials"); err != nil {
		t.Fatal(err)
	}
	deks.keys[deks.id(orgB, "credentials", 1)] = deks.keys[deks.id(orgA, "credentials", 1)]
	moved := map[string]FieldContext{
		"other org":    {Org: orgB, Table: home.Table, Column: home.Column, RowID: home.RowID},
		"other table":  {Org: orgA, Table: "api_keys", Column: home.Column, RowID: home.RowID},
		"other column": {Org: orgA, Table: home.Table, Column: "label", RowID: home.RowID},
		"other row":    {Org: orgA, Table: home.Table, Column: home.Column, RowID: "row-2"},
	}
	for name, fc := range moved {
		if _, err := env.Decrypt(ctx, fc, "credentials", blob); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: ciphertext swap not detected (err %v)", name, err)
		}
	}
	if _, err := env.Decrypt(ctx, home, "other-purpose", blob); !errors.Is(err, ErrDecrypt) {
		t.Error("purpose swap not detected")
	}
}

func TestT016_EnvelopeRejectsHeaderTampering(t *testing.T) {
	ctx := context.Background()
	deks := newMemDEKs()
	env := NewEnvelope(deks)
	fc := FieldContext{Org: ids.New[ids.Org](), Table: "t", Column: "c", RowID: "r"}
	blob, err := env.Encrypt(ctx, fc, "p", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	// Rotate: version 2 exists; relabeling a v1 blob as v2 must fail.
	deks.current = 2
	if _, _, err := deks.CurrentDEK(ctx, fc.Org, "p"); err != nil {
		t.Fatal(err)
	}
	relabeled := bytes.Clone(blob)
	relabeled[4] = 2
	if _, err := env.Decrypt(ctx, fc, "p", relabeled); !errors.Is(err, ErrDecrypt) {
		t.Fatal("DEK version relabeling not detected")
	}
	// Old version still decrypts after rotation.
	if pt, err := env.Decrypt(ctx, fc, "p", blob); err != nil || string(pt) != "x" {
		t.Fatalf("decrypt after rotation = %q, %v", pt, err)
	}
	for name, b := range map[string][]byte{
		"empty":       nil,
		"bad version": append([]byte{0x02}, blob[1:]...),
		"header only": blob[:5],
	} {
		if _, err := env.Decrypt(ctx, fc, "p", b); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	unknown := bytes.Clone(blob)
	unknown[4] = 9
	if _, err := env.Decrypt(ctx, fc, "p", unknown); !errors.Is(err, ErrDecrypt) {
		t.Error("unknown DEK version should look like any other decryption failure")
	}
}

func TestEnvelopeRequiresCompleteContext(t *testing.T) {
	env := NewEnvelope(newMemDEKs())
	for name, fc := range map[string]FieldContext{
		"no org":    {Table: "t", Column: "c", RowID: "r"},
		"no table":  {Org: ids.New[ids.Org](), Column: "c", RowID: "r"},
		"no column": {Org: ids.New[ids.Org](), Table: "t", RowID: "r"},
		"no row":    {Org: ids.New[ids.Org](), Table: "t", Column: "c"},
	} {
		if _, err := env.Encrypt(context.Background(), fc, "p", []byte("x")); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("%s: err = %v, want ErrInvalidContext", name, err)
		}
	}
}

func TestSealOpen(t *testing.T) {
	for _, suite := range availableSuites() {
		t.Run(suite.String(), func(t *testing.T) { testSealOpen(t, suite) })
	}
}

func testSealOpen(t *testing.T, suite SealSuite) {
	priv, err := GenerateSealKeySuite(suite)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := priv.PublicKey().Bytes()
	pub, err := ParseSealPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("pc-cred-v1|org|conn|1|api.stripe.com")
	sealed, err := Seal(pub, info, []byte("aad"), []byte("sk_test_not_real"))
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := ParseSealPrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(priv2, info, []byte("aad"), sealed)
	if err != nil || string(pt) != "sk_test_not_real" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
	other, _ := GenerateSealKeySuite(suite)
	for name, try := range map[string]func() error{
		"wrong key": func() error { _, err := Open(other, info, []byte("aad"), sealed); return err },
		"wrong info": func() error {
			_, err := Open(priv, []byte("pc-cred-v1|org|conn|2|x"), []byte("aad"), sealed)
			return err
		},
		"wrong aad": func() error { _, err := Open(priv, info, []byte("aae"), sealed); return err },
		"tampered": func() error {
			bad := bytes.Clone(sealed)
			bad[len(bad)-1] ^= 1
			_, err := Open(priv, info, []byte("aad"), bad)
			return err
		},
	} {
		if err := try(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"empty": nil, "bad version": {0x09, 0, 0}, "short enc": {0x01, 0xff, 0xff, 1},
		"short v2 enc": {0x02, 0x00, 0x50, 0xff, 0xff, 1}, "unknown suite": {0x02, 0x00, 0x20, 0, 0},
	} {
		if _, err := Open(priv, info, nil, b); !errors.Is(err, ErrSealedFormat) {
			t.Errorf("%s: err = %v, want ErrSealedFormat", name, err)
		}
	}
	if _, err := Seal(pub, nil, nil, []byte("x")); !errors.Is(err, ErrInvalidContext) {
		t.Error("Seal without info must be refused")
	}
}
