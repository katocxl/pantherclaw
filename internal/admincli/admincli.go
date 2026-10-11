// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package admincli implements pclaw-admin, the offline tool for the
// founder's root keys (HR-063): root key generation, licence signing and
// verification, and tool package targets signing and verification. It has
// no network code and must only run on an offline-capable machine; the root
// private keys never enter CI.
package admincli

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/billing/licence"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

const usage = `pclaw-admin — offline root key, licence and package signing tool (keep this machine offline)

Usage:
  pclaw-admin keygen --purpose licence|packages --out-dir DIR [--passphrase-file FILE]
  pclaw-admin licence sign --key FILE [--passphrase-file FILE] --claims FILE --out FILE
  pclaw-admin licence verify --roots FILE --in FILE
  pclaw-admin packages sign --key FILE [--passphrase-file FILE] --version N [--expires-days 180] --out FILE PACKAGE.yaml...
  pclaw-admin packages verify --roots FILE --targets FILE PACKAGE.yaml...
  pclaw-admin version

Flags come before the package files.
`

// Run executes pclaw-admin with args (without the program name).
func Run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	var err error
	switch {
	case args[0] == "version" || args[0] == "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pclaw-admin"))
		return exitOK
	case args[0] == "keygen":
		err = keygen(args[1:], stdout, stderr)
	case args[0] == "licence" && len(args) > 1 && args[1] == "sign":
		err = sign(args[2:], stdout, stderr, now)
	case args[0] == "licence" && len(args) > 1 && args[1] == "verify":
		err = verify(args[2:], stdout, stderr, now)
	case args[0] == "packages" && len(args) > 1 && args[1] == "sign":
		err = signPackages(args[2:], stdout, stderr, now)
	case args[0] == "packages" && len(args) > 1 && args[1] == "verify":
		err = verifyPackages(args[2:], stdout, stderr, now)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if errors.Is(err, flag.ErrHelp) || errors.Is(err, errUsage) {
		return exitUsage
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pclaw-admin: %v\n", err)
		return exitError
	}
	return exitOK
}

var errUsage = errors.New("usage")

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func passphrase(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	s, err := config.ReadSecretFile(path)
	if err != nil {
		return nil, err
	}
	return s.Reveal(), nil
}

// loadSigner decodes a root private key and refuses a root of another
// purpose.
func loadSigner(keyFile, ppFile string, want ...rootkey.Purpose) (*jws.Signer, error) {
	pp, err := passphrase(ppFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // G304: operator-chosen key path
	if err != nil {
		return nil, err
	}
	p, priv, err := rootkey.Decode(keyPEM, pp)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(want, p) {
		return nil, fmt.Errorf("key %s is a %s key, not a %s root", keyFile, p, want[0])
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	return jws.NewSigner(rootkey.KID(p, pub), priv)
}

func keygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("keygen", stderr)
	purpose := fs.String("purpose", "", "licence or packages")
	outDir := fs.String("out-dir", "", "directory for the key files (offline media)")
	ppFile := fs.String("passphrase-file", "", "file holding a passphrase (≥ 16 characters) to encrypt the private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := rootkey.Purpose(*purpose)
	if !p.Root() || *outDir == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	pp, err := passphrase(*ppFile)
	if err != nil {
		return err
	}
	priv, kid, err := rootkey.Generate(p)
	if err != nil {
		return err
	}
	privPEM, err := rootkey.Encode(p, priv, pp)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	jwks, err := json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{Keys: []jws.JWK{jws.PublicJWK(pub, kid)}})
	if err != nil {
		return err
	}
	privPath := filepath.Join(*outDir, string(p)+"-root.key")
	pubPath := filepath.Join(*outDir, string(p)+"-root.pub.json")
	if err := rootkey.WriteNew(privPath, privPEM); err != nil {
		return err
	}
	if err := rootkey.WriteNew(pubPath, append(jwks, '\n')); err != nil {
		return err
	}
	encrypted := "UNENCRYPTED (store only on encrypted offline media)"
	if len(pp) > 0 {
		encrypted = "encrypted with your passphrase"
	}
	_, _ = fmt.Fprintf(stdout, "Generated %s root key %s\n  private key: %s (%s)\n  public key:  %s\n\n", p, kid, privPath, encrypted, pubPath)
	_, _ = fmt.Fprintf(stdout, "Next steps:\n  1. Copy the private key to a second offline medium. Never copy it to CI or a server.\n")
	roots := "internal/billing/licence/roots.json"
	if p == rootkey.PurposePackages {
		roots = "internal/definitions/trust/roots.json"
	}
	_, _ = fmt.Fprintf(stdout, "  2. Add the key from %s to %s and commit it.\n", pubPath, roots)
	return nil
}

// claimsInput is the human-written licence request.
type claimsInput struct {
	LicenceID  string         `json:"lid"`
	Licensee   string         `json:"sub"`
	CustomerID string         `json:"cid"`
	Edition    domain.Edition `json:"edition"`
	MaxAgents  int            `json:"max_agents"`
	MaxOrgs    int            `json:"max_orgs"`
	NotBefore  time.Time      `json:"not_before"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

func sign(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("licence sign", stderr)
	keyFile := fs.String("key", "", "licence root private key file")
	ppFile := fs.String("passphrase-file", "", "passphrase file for an encrypted key")
	claimsFile := fs.String("claims", "", "JSON claims: sub, cid, edition, max_agents, max_orgs, not_before, expires_at [, lid]")
	out := fs.String("out", "", "output licence file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *claimsFile == "" || *out == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	signer, err := loadSigner(*keyFile, *ppFile, rootkey.PurposeLicence)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*claimsFile)
	if err != nil {
		return err
	}
	var in claimsInput
	if err := json.Unmarshal(raw, &in, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("claims: %w", err)
	}
	if in.LicenceID == "" {
		in.LicenceID = ids.NewV7().String()
	}
	c := domain.Claims{
		Version: 1, LicenceID: in.LicenceID, Licensee: in.Licensee, CustomerID: in.CustomerID,
		Edition: in.Edition, MaxAgents: in.MaxAgents, MaxOrgs: in.MaxOrgs,
		IssuedAt: now().UTC().Truncate(time.Second), NotBefore: in.NotBefore.UTC(), ExpiresAt: in.ExpiresAt.UTC(),
	}
	doc, err := licence.Sign(c, signer)
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(*out, doc); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Signed licence %s for %s (%s, %d agents, %d orgs, valid %s → %s) → %s\n",
		c.LicenceID, c.Licensee, c.Edition, c.MaxAgents, c.MaxOrgs,
		c.NotBefore.Format(time.DateOnly), c.ExpiresAt.Format(time.DateOnly), *out)
	return nil
}

func verify(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("licence verify", stderr)
	rootsFile := fs.String("roots", "", "JWKS with licence root public keys")
	in := fs.String("in", "", "licence file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootsFile == "" || *in == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	rb, err := os.ReadFile(*rootsFile)
	if err != nil {
		return err
	}
	roots, err := licence.ParseRoots(rb)
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	c, err := licence.Verify(doc, roots)
	if err != nil {
		return err
	}
	e := domain.Evaluate(c, now())
	_, _ = fmt.Fprintf(stdout, "Licence %s for %s (customer %s)\n  edition %s, %d agents, %d orgs\n  valid %s → %s\n  status now: %s\n",
		c.LicenceID, c.Licensee, c.CustomerID, c.Edition, c.MaxAgents, c.MaxOrgs,
		c.NotBefore.Format(time.RFC3339), c.ExpiresAt.Format(time.RFC3339), e.Status)
	if e.Warning != "" {
		_, _ = fmt.Fprintf(stdout, "  warning: %s\n", e.Warning)
	}
	return nil
}
