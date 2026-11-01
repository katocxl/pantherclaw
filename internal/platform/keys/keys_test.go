// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

func kekFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := GenerateKEKFile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileProviderWrapUnwrapAndRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	k1 := kekFile(t, dir, "kek1")
	k2 := kekFile(t, dir, "kek2")

	old, err := NewFileProvider([]string{k1})
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := old.Wrap(ctx, []byte("dek-bytes"), []byte("dek|org|purpose|1"))
	if err != nil {
		t.Fatal(err)
	}
	// Rotation: k2 becomes current, k1 stays for unwrapping.
	rotated, err := NewFileProvider([]string{k2, k1})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.CurrentKEK() == old.CurrentKEK() {
		t.Fatal("current KEK did not change")
	}
	pt, err := rotated.Unwrap(ctx, wrapped, []byte("dek|org|purpose|1"))
	if err != nil || string(pt) != "dek-bytes" {
		t.Fatalf("unwrap after rotation = %q, %v", pt, err)
	}
	// Without the old KEK the value cannot be unwrapped.
	only2, _ := NewFileProvider([]string{k2})
	if _, err := only2.Unwrap(ctx, wrapped, []byte("dek|org|purpose|1")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("unwrap without KEK: %v", err)
	}
	for name, try := range map[string]func() error{
		"wrong aad": func() error { _, err := old.Unwrap(ctx, wrapped, []byte("dek|org|purpose|2")); return err },
		"tampered": func() error {
			bad := bytes.Clone(wrapped)
			bad[len(bad)-1] ^= 1
			_, err := old.Unwrap(ctx, bad, []byte("dek|org|purpose|1"))
			return err
		},
		"truncated": func() error { _, err := old.Unwrap(ctx, wrapped[:3], []byte("x")); return err },
		"empty":     func() error { _, err := old.Unwrap(ctx, nil, []byte("x")); return err },
	} {
		if err := try(); !errors.Is(err, ErrUnwrap) {
			t.Errorf("%s: err = %v, want ErrUnwrap", name, err)
		}
	}
	if _, err := old.Wrap(ctx, []byte("x"), nil); err == nil {
		t.Error("Wrap without associated data accepted")
	}
}

func TestFileProviderRejectsBadKEKFiles(t *testing.T) {
	dir := t.TempDir()
	k1 := kekFile(t, dir, "kek1")
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte(base64.StdEncoding.EncodeToString(make([]byte, 16))), 0o600)
	garbage := filepath.Join(dir, "garbage")
	_ = os.WriteFile(garbage, []byte("not base64!!"), 0o600)
	for name, paths := range map[string][]string{
		"none":      nil,
		"short":     {short},
		"garbage":   {garbage},
		"duplicate": {k1, k1},
		"missing":   {filepath.Join(dir, "nope")},
	} {
		if _, err := NewFileProvider(paths); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := GenerateKEKFile(k1); err == nil {
		t.Error("GenerateKEKFile overwrote an existing file")
	}
}

func TestThumbprintRFC8037(t *testing.T) {
	// RFC 8037 Appendix A.3.
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if got := jws.Thumbprint(ed25519.PublicKey(x)); got != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint = %s", got)
	}
}

func TestRegistrySeparatesPurposes(t *testing.T) {
	r := NewRegistry()
	permits, _ := GenerateSigningKey(PurposePermits)
	receipts, _ := GenerateSigningKey(PurposeReceipts)
	for _, k := range []SigningKey{permits, receipts} {
		if err := r.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	s, err := r.Signer(PurposePermits)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.Sign("pap-permit+jwt", []byte(`{}`))
	pv, _ := r.Verifier(PurposePermits, "pap-permit+jwt")
	if _, _, err := pv.Verify(tok); err != nil {
		t.Fatalf("permit verifier rejected a permit: %v", err)
	}
	// A receipt verifier must not accept a permit-key signature, even if the
	// typ is made to match.
	rs, _ := r.Signer(PurposePermits)
	forged, _ := rs.Sign("pap-decision+jwt", []byte(`{}`))
	rv, _ := r.Verifier(PurposeReceipts, "pap-decision+jwt")
	if _, _, err := rv.Verify(forged); !errors.Is(err, jws.ErrInvalid) {
		t.Fatalf("receipt verifier accepted a permit key: %v", err)
	}
}

func TestRegistryRotationAndRevocation(t *testing.T) {
	r := NewRegistry()
	k1, _ := GenerateSigningKey(PurposeReceipts)
	k2, _ := GenerateSigningKey(PurposeReceipts)
	if err := r.Put(k1); err != nil {
		t.Fatal(err)
	}
	if err := r.Put(k2); err == nil {
		t.Fatal("two active keys for one purpose accepted")
	}
	s1, _ := r.Signer(PurposeReceipts)
	oldTok, _ := s1.Sign("pap-decision+jwt", []byte(`{"n":1}`))

	k1.State = StateRetiring
	if err := r.Put(k1); err != nil {
		t.Fatal(err)
	}
	if err := r.Put(k2); err != nil {
		t.Fatal(err)
	}
	s2, _ := r.Signer(PurposeReceipts)
	if s2.KeyID() != k2.KID {
		t.Fatalf("signer kid = %s, want new key %s", s2.KeyID(), k2.KID)
	}
	v, _ := r.Verifier(PurposeReceipts, "pap-decision+jwt")
	if _, _, err := v.Verify(oldTok); err != nil {
		t.Fatalf("retiring key no longer verifies during overlap: %v", err)
	}
	k1.State = StateRevoked
	_ = r.Put(k1)
	v, _ = r.Verifier(PurposeReceipts, "pap-decision+jwt")
	if _, _, err := v.Verify(oldTok); !errors.Is(err, jws.ErrInvalid) {
		t.Fatal("revoked key still verifies")
	}
	jwks, _ := r.JWKS()
	if strings.Contains(string(jwks), k1.KID) || !strings.Contains(string(jwks), k2.KID) {
		t.Fatalf("JWKS = %s", jwks)
	}
}

func TestRegistryRejectsInconsistentKeys(t *testing.T) {
	r := NewRegistry()
	k, _ := GenerateSigningKey(PurposePermits)
	other, _ := GenerateSigningKey(PurposePermits)
	bad := []SigningKey{
		{KID: "x", Purpose: PurposePermits, State: StateActive, Public: k.Public, Private: k.Private},
		{KID: k.KID, Purpose: PurposeReceipts, State: StateActive, Public: k.Public, Private: k.Private},
		{KID: k.KID, Purpose: PurposePermits, State: StateActive, Public: k.Public, Private: other.Private},
		{KID: k.KID, Purpose: PurposePermits, State: StateActive, Public: k.Public},
		{KID: k.KID, Purpose: PurposePermits, State: "WHATEVER", Public: k.Public, Private: k.Private},
		{KID: k.KID, Purpose: "admin", State: StateActive, Public: k.Public, Private: k.Private},
	}
	for i, b := range bad {
		if err := r.Put(b); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	verifyOnly := SigningKey{KID: k.KID, Purpose: PurposePermits, State: StateRetiring, Public: k.Public, Private: pclog.Secret[ed25519.PrivateKey]{}}
	if err := r.Put(verifyOnly); err != nil {
		t.Fatalf("verify-only key rejected: %v", err)
	}
	if _, err := r.Signer(PurposePermits); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Signer without active key: %v", err)
	}
}

func TestJWKSDocument(t *testing.T) {
	r := NewRegistry()
	for _, p := range Purposes() {
		k, err := GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	b, err := r.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 5 {
		t.Fatalf("JWKS has %d keys, want 5 (checkpoint, access-token and gateway CA keys are not published)", len(doc.Keys))
	}
	for _, k := range doc.Keys {
		for _, hidden := range []Purpose{PurposeCheckpoints, PurposeAccessTokens, PurposeGatewayCA} {
			if strings.HasPrefix(k.Kid, strings.ReplaceAll(string(hidden), "_", "-")+"-") {
				t.Errorf("JWKS publishes a %s key", hidden)
			}
		}
	}
	for _, k := range doc.Keys {
		if k.Alg != "EdDSA" || k.Use != "sig" || k.Kty != "OKP" || k.Crv != "Ed25519" {
			t.Errorf("bad JWK %+v", k)
		}
		if _, err := k.Key(); err != nil {
			t.Errorf("JWK %s does not parse: %v", k.Kid, err)
		}
		if strings.Contains(string(b), `"d"`) {
			t.Fatal("JWKS contains private key material")
		}
	}
	empty, _ := NewRegistry().JWKS()
	if string(empty) != `{"keys":[]}` {
		t.Fatalf("empty JWKS = %s", empty)
	}
}
