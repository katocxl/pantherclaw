// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package crypto

import (
	"crypto/fips140"
	"errors"
	"testing"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// availableSuites are the suites this process may use: X-Wing only outside
// FIPS mode.
func availableSuites() []SealSuite {
	if fipsMode() {
		return []SealSuite{SuiteMLKEM768P256}
	}
	return []SealSuite{SuiteXWing, SuiteMLKEM768P256}
}

// setFIPS overrides FIPS mode for one test.
func setFIPS(t *testing.T, on bool) {
	t.Helper()
	prev := fipsMode
	fipsMode = func() bool { return on }
	t.Cleanup(func() { fipsMode = prev })
}

// xwingFixture seals a credential with X-Wing outside FIPS mode, both as a
// current (v2) blob and as a blob from before M13 (v1, no suite field).
func xwingFixture(t *testing.T) (priv *SealPrivateKey, privBytes, pubBytes, v2, v1 []byte) {
	t.Helper()
	setFIPS(t, false)
	priv, err := GenerateSealKeySuite(SuiteXWing)
	if err != nil {
		t.Fatal(err)
	}
	if privBytes, err = priv.Bytes(); err != nil {
		t.Fatal(err)
	}
	pubBytes = priv.PublicKey().Bytes()
	if v2, err = Seal(priv.PublicKey(), []byte("info"), []byte("aad"), []byte("secret")); err != nil {
		t.Fatal(err)
	}
	v1 = append([]byte{sealedV1}, v2[3:]...)
	return priv, privBytes, pubBytes, v2, v1
}

// Blobs sealed with X-Wing before M13 keep opening outside FIPS mode, and
// new blobs record their suite (D35).
func TestSealSuiteRecordedAndV1StillOpens(t *testing.T) {
	priv, privBytes, _, v2, v1 := xwingFixture(t)
	if len(privBytes) != seedSize {
		t.Fatalf("an X-Wing private key is %d bytes, want the bare %d-byte seed (keys from before M13)", len(privBytes), seedSize)
	}
	for name, blob := range map[string][]byte{"v1": v1, "v2": v2} {
		if s, err := SealedSuite(blob); err != nil || s != SuiteXWing {
			t.Errorf("%s: SealedSuite = %v, %v", name, s, err)
		}
		if pt, err := Open(priv, []byte("info"), []byte("aad"), blob); err != nil || string(pt) != "secret" {
			t.Errorf("%s: Open = %q, %v", name, pt, err)
		}
	}
	p, err := GenerateSealKeySuite(SuiteMLKEM768P256)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Bytes()
	if err != nil || len(b) != 2+seedSize {
		t.Fatalf("an MLKEM768-P256 private key = %d bytes, %v", len(b), err)
	}
	p2, err := ParseSealPrivateKey(b)
	if err != nil || p2.Suite() != SuiteMLKEM768P256 {
		t.Fatalf("ParseSealPrivateKey = %v, %v", p2, err)
	}
	sealed, err := Seal(p.PublicKey(), []byte("info"), nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := SealedSuite(sealed); s != SuiteMLKEM768P256 {
		t.Errorf("SealedSuite = %v", s)
	}
	// A blob of one suite never opens with a key of the other.
	if _, err := Open(priv, []byte("info"), nil, sealed); !errors.Is(err, ErrDecrypt) {
		t.Errorf("an MLKEM768-P256 blob with an X-Wing key: %v, want ErrDecrypt", err)
	}
	if _, err := Open(p2, []byte("info"), []byte("aad"), v2); !errors.Is(err, ErrDecrypt) {
		t.Errorf("an X-Wing blob with an MLKEM768-P256 key: %v, want ErrDecrypt", err)
	}
	if DefaultSealSuite() != SuiteXWing {
		t.Errorf("outside FIPS mode the default suite is %v, want X-Wing", DefaultSealSuite())
	}
}

// TestHR396_XWingRefusedInFIPSMode: in FIPS mode new keys are MLKEM768-P256
// and every X-Wing key or blob is refused with SEAL_SUITE_NOT_FIPS.
func TestHR396_XWingRefusedInFIPSMode(t *testing.T) {
	priv, privBytes, pubBytes, v2, v1 := xwingFixture(t)
	setFIPS(t, true)
	for name, try := range map[string]func() error{
		"open v1":    func() error { _, err := Open(priv, []byte("info"), []byte("aad"), v1); return err },
		"open v2":    func() error { _, err := Open(priv, []byte("info"), []byte("aad"), v2); return err },
		"parse priv": func() error { _, err := ParseSealPrivateKey(privBytes); return err },
		"parse pub":  func() error { _, err := ParseSealPublicKey(pubBytes); return err },
		"seal":       func() error { _, err := Seal(priv.PublicKey(), []byte("info"), nil, []byte("x")); return err },
		"generate":   func() error { _, err := GenerateSealKeySuite(SuiteXWing); return err },
	} {
		err := try()
		if !errors.Is(err, ErrSealSuiteNotFIPS) || pcerr.ReasonOf(err) != "SEAL_SUITE_NOT_FIPS" {
			t.Errorf("%s in FIPS mode: %v, want SEAL_SUITE_NOT_FIPS", name, err)
		}
	}
	k, err := GenerateSealKey()
	if err != nil || k.Suite() != SuiteMLKEM768P256 {
		t.Fatalf("GenerateSealKey in FIPS mode = %v, %v; want MLKEM768-P256", k, err)
	}
	pub, err := ParseSealPublicKey(k.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(pub, []byte("info"), nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := Open(k, []byte("info"), nil, sealed); err != nil || string(pt) != "x" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
}

// TestHR396_FIPSBuildSealsWithMLKEM768P256 runs in the fips140=only job
// (task test:fips): the real FIPS switch picks the FIPS suite.
func TestHR396_FIPSBuildSealsWithMLKEM768P256(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("runs with GODEBUG=fips140=on|only (task test:fips)")
	}
	if DefaultSealSuite() != SuiteMLKEM768P256 {
		t.Fatalf("in a FIPS build the default suite is %v", DefaultSealSuite())
	}
	if _, err := GenerateSealKeySuite(SuiteXWing); !errors.Is(err, ErrSealSuiteNotFIPS) {
		t.Fatalf("X-Wing in a FIPS build: %v", err)
	}
}
