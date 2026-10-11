// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package admincli

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

var mockPayments = filepath.Join("..", "..", "packages", "mock-payments", "package.yaml")

func TestHR123_PackagesSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pp := write(t, dir, "pass", "a long offline passphrase\n")
	code, out, errs := run(t, "keygen", "--purpose", "packages", "--out-dir", dir, "--passphrase-file", pp)
	if code != 0 || !strings.Contains(out, "internal/definitions/trust/roots.json") {
		t.Fatalf("keygen exit %d:\n%s%s", code, out, errs)
	}
	key, roots := filepath.Join(dir, "packages-root.key"), filepath.Join(dir, "packages-root.pub.json")
	targets := filepath.Join(dir, "targets.jws")
	code, out, errs = run(t, "packages", "sign", "--key", key, "--passphrase-file", pp,
		"--version", "7", "--expires-days", "180", "--out", targets, mockPayments)
	if code != 0 || !strings.Contains(out, "pc.mock-payments@1.0.0  sha256:") || !strings.Contains(out, "packages-root-") {
		t.Fatalf("sign exit %d:\n%s%s", code, out, errs)
	}

	// The document verifies with the trust package, as the importer will.
	rb, _ := os.ReadFile(roots)
	r, err := trust.ParseRoots(rb)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := os.ReadFile(targets)
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	v, err := trust.Verify(string(doc), r, now)
	if err != nil || v.Version != 7 || v.Expires != "2027-04-06T12:00:00Z" || len(v.Targets.Targets) != 1 {
		t.Fatalf("verified %+v, %v", v.Targets, err)
	}
	raw, _ := os.ReadFile(mockPayments)
	if _, err := v.Match("pc.mock-payments", "1.0.0", raw); err != nil {
		t.Fatal(err)
	}

	code, out, errs = run(t, "packages", "verify", "--roots", roots, "--targets", targets, mockPayments)
	if code != 0 || !strings.Contains(out, "version 7") || !strings.Contains(out, "pc.mock-payments@1.0.0") || !strings.Contains(out, "OK") {
		t.Fatalf("verify exit %d:\n%s%s", code, out, errs)
	}
	// A comment changes the bytes but not the meaning; it still must not verify.
	edited := write(t, dir, "edited.yaml", string(raw)+"# edited\n")
	if code, _, errs := run(t, "packages", "verify", "--roots", roots, "--targets", targets, edited); code != exitError || !strings.Contains(errs, "does not match") {
		t.Fatalf("edited package verified: %d %s", code, errs)
	}
	if code, _, _ := run(t, "packages", "sign", "--key", key, "--passphrase-file", pp,
		"--version", "8", "--expires-days", "180", "--out", targets, mockPayments); code == 0 {
		t.Fatal("sign overwrote an existing targets file")
	}
}

// TestPackagesSignDefaultsTo180Days: without --expires-days the targets
// expire after 180 days (G0 M4 decision 1).
func TestPackagesSignDefaultsTo180Days(t *testing.T) {
	dir := t.TempDir()
	if code, _, errs := run(t, "keygen", "--purpose", "packages", "--out-dir", dir); code != 0 {
		t.Fatal(errs)
	}
	targets := filepath.Join(dir, "targets.jws")
	if code, out, errs := run(t, "packages", "sign", "--key", filepath.Join(dir, "packages-root.key"),
		"--version", "1", "--out", targets, mockPayments); code != 0 {
		t.Fatalf("sign exit %d: %s%s", code, out, errs)
	}
	rb, _ := os.ReadFile(filepath.Join(dir, "packages-root.pub.json"))
	r, err := trust.ParseRoots(rb)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := os.ReadFile(targets)
	v, err := trust.Verify(string(doc), r, time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC))
	if err != nil || v.Expires != "2027-04-06T12:00:00Z" {
		t.Fatalf("expires %q, %v; want 180 days after signing", v.Expires, err)
	}
}

func TestHR063_PackagesSignRefusals(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"licence", "packages"} {
		if code, _, errs := run(t, "keygen", "--purpose", p, "--out-dir", dir); code != 0 {
			t.Fatal(errs)
		}
	}
	raw, err := os.ReadFile(mockPayments)
	if err != nil {
		t.Fatal(err)
	}
	unknownField := write(t, dir, "unknown.yaml", string(raw)+"unexpected: true\n")
	anchor := write(t, dir, "anchor.yaml", "format: 1\nname: &n pc.anchored\n")
	pkgKey := filepath.Join(dir, "packages-root.key")
	out := filepath.Join(dir, "targets.jws")
	cases := map[string]struct {
		args []string
		want string
	}{
		"licence root":    {[]string{"--key", filepath.Join(dir, "licence-root.key"), mockPayments}, "not a packages root"},
		"unknown field":   {[]string{"--key", pkgKey, mockPayments, unknownField}, "invalid package file"},
		"anchor":          {[]string{"--key", pkgKey, anchor}, "invalid package file"},
		"listed twice":    {[]string{"--key", pkgKey, mockPayments, mockPayments}, "listed twice"},
		"expiry too long": {[]string{"--key", pkgKey, "--expires-days", "400", mockPayments}, "between 1 and 365"},
		"no expiry":       {[]string{"--key", pkgKey, "--expires-days", "0", mockPayments}, "between 1 and 365"},
	}
	for name, c := range cases {
		args := append([]string{"packages", "sign", "--version", "1", "--expires-days", "180", "--out", out}, c.args...)
		if code, _, errs := run(t, args...); code != exitError || !strings.Contains(errs, c.want) {
			t.Errorf("%s: exit %d, stderr %q, want %q", name, code, errs, c.want)
		}
		if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s: a targets file was written", name)
		}
	}
}

func TestT036_PackagesVerifyRefusesOtherRoot(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	for _, d := range []string{dir, other} {
		if code, _, errs := run(t, "keygen", "--purpose", "packages", "--out-dir", d); code != 0 {
			t.Fatal(errs)
		}
	}
	targets := filepath.Join(dir, "targets.jws")
	if code, _, errs := run(t, "packages", "sign", "--key", filepath.Join(dir, "packages-root.key"),
		"--version", "1", "--expires-days", "30", "--out", targets, mockPayments); code != 0 {
		t.Fatal(errs)
	}
	if code, _, errs := run(t, "packages", "verify", "--roots", filepath.Join(other, "packages-root.pub.json"), "--targets", targets, mockPayments); code != exitError || !strings.Contains(errs, "untrusted") {
		t.Fatalf("verified against another root: %d %s", code, errs)
	}
	empty := write(t, dir, "roots.json", `{"keys":[]}`)
	if code, _, errs := run(t, "packages", "verify", "--roots", empty, "--targets", targets, mockPayments); code != exitError || !strings.Contains(errs, "no package root keys") {
		t.Fatalf("empty roots: %d %s", code, errs)
	}
}

// TestHR163_PackagesSignWithTheDevelopmentKey: the development package key
// that dev seed keeps signs targets like the package root, and says so; it
// is never accepted as a package root by verify.
func TestHR163_PackagesSignWithTheDevelopmentKey(t *testing.T) {
	dir := t.TempDir()
	priv, kid, err := rootkey.Generate(rootkey.PurposeDevPackages)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := rootkey.Encode(rootkey.PurposeDevPackages, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := write(t, dir, "package-dev.key", string(pem))
	pub, _ := priv.Public().(ed25519.PublicKey)
	devJWKS, err := json.Marshal(map[string][]jws.JWK{"keys": {jws.PublicJWK(pub, kid)}})
	if err != nil {
		t.Fatal(err)
	}
	pubFile := write(t, dir, "package-dev.pub.json", string(devJWKS))
	targets := filepath.Join(dir, "targets.jws")
	code, out, errs := run(t, "packages", "sign", "--key", key, "--version", "2", "--expires-days", "30", "--out", targets, mockPayments)
	if code != 0 || !strings.Contains(out, kid) || !strings.Contains(out, "development package key") {
		t.Fatalf("sign exit %d:\n%s%s", code, out, errs)
	}
	doc, _ := os.ReadFile(targets)
	dev, err := trust.ParseDevKey(devJWKS)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := trust.Verify(string(doc), dev, time.Now()); err != nil || v.KID != kid {
		t.Fatalf("verified %v, %v", v.KID, err)
	}
	if code, _, errs := run(t, "packages", "verify", "--roots", pubFile, "--targets", targets, mockPayments); code != exitError || !strings.Contains(errs, "does not match its key") {
		t.Fatalf("the development key verified as a package root: %d %s", code, errs)
	}
}
