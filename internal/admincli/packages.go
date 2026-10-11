// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package admincli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// maxExpiryDays bounds --expires-days. A signed targets document stays valid
// until it expires, so a typo must not sign one for years. defaultExpiryDays
// is G0 M4 decision 1: the signed list is valid for 180 days and checked
// only at import.
const (
	maxExpiryDays     = 365
	defaultExpiryDays = 180
)

// signPackages signs a targets document listing the exact bytes of each
// package file (HR-123). The expiry defaults to 180 days (G0 M4 decision 1).
func signPackages(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("packages sign", stderr)
	keyFile := fs.String("key", "", "packages root private key file")
	ppFile := fs.String("passphrase-file", "", "passphrase file for an encrypted key")
	version := fs.Int64("version", 0, "targets version, higher than the last one published")
	days := fs.Int("expires-days", defaultExpiryDays, fmt.Sprintf("days until the targets expire, 1..%d", maxExpiryDays))
	out := fs.String("out", "", "output targets file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *version < 1 || *out == "" || fs.NArg() == 0 {
		fs.Usage()
		return errUsage
	}
	if *days < 1 || *days > maxExpiryDays {
		return fmt.Errorf("--expires-days must be between 1 and %d", maxExpiryDays)
	}
	// The development package key `dev seed` keeps signs the same way; only
	// local servers trust it (HR-163).
	signer, err := loadSigner(*keyFile, *ppFile, rootkey.PurposePackages, rootkey.PurposeDevPackages)
	if err != nil {
		return err
	}
	t := trust.Targets{
		Version: *version,
		Expires: now().UTC().Truncate(time.Second).AddDate(0, 0, *days).Format(time.RFC3339),
		Targets: map[string]trust.Target{},
	}
	var listed []string
	for _, path := range fs.Args() {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen package path
		if err != nil {
			return err
		}
		p, err := manifest.Decode(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		key := trust.Key(p.Name, p.Version)
		if _, dup := t.Targets[key]; dup {
			return fmt.Errorf("%s: %s is listed twice", path, key)
		}
		sum := sha256.Sum256(raw)
		t.Targets[key] = trust.Target{Length: int64(len(raw)), Hashes: map[string]string{"sha256": hex.EncodeToString(sum[:])}}
		listed = append(listed, fmt.Sprintf("  %s  %s  %d bytes  (%s)\n", key, manifest.FileDigest(raw), len(raw), path))
	}
	doc, err := trust.Sign(t, signer)
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(*out, []byte(doc+"\n")); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Signed package targets version %d with %s, expires %s → %s\n", t.Version, signer.KeyID(), t.Expires, *out)
	if trust.IsDevKID(signer.KeyID()) {
		_, _ = fmt.Fprint(stdout, "This is the development package key: only a local server with dev.package_key_file trusts it.\n")
	}
	for _, l := range listed {
		_, _ = fmt.Fprint(stdout, l)
	}
	_, _ = fmt.Fprintf(stdout, "Sign the next targets with --version %d or higher: installations refuse an older version, and different targets under the same one.\n", t.Version+1)
	return nil
}

// verifyPackages is a dry run of an import: the targets document must verify
// against roots now, and each package file must be valid and listed with its
// exact length and hash.
func verifyPackages(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("packages verify", stderr)
	rootsFile := fs.String("roots", "", "JWKS with package root public keys")
	targetsFile := fs.String("targets", "", "signed targets file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootsFile == "" || *targetsFile == "" || fs.NArg() == 0 {
		fs.Usage()
		return errUsage
	}
	rb, err := os.ReadFile(*rootsFile)
	if err != nil {
		return err
	}
	roots, err := trust.ParseRoots(rb)
	if err != nil {
		return err
	}
	if len(roots) == 0 {
		return fmt.Errorf("%s holds no package root keys", *rootsFile)
	}
	doc, err := os.ReadFile(*targetsFile)
	if err != nil {
		return err
	}
	v, err := trust.Verify(string(doc), roots, now())
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Targets version %d (%d listed) signed by %s, expires %s (in %d days)\n",
		v.Version, len(v.Targets.Targets), v.KID, v.Expires, int(v.Expiry.Sub(now()).Hours()/24))
	for _, path := range fs.Args() {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-chosen package path
		if err != nil {
			return err
		}
		p, err := manifest.Decode(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		digest, err := v.Match(p.Name, p.Version, raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		_, _ = fmt.Fprintf(stdout, "  %s  %s  OK  (%s)\n", trust.Key(p.Name, p.Version), digest, path)
	}
	return nil
}
