// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/katocxl/pantherclaw/internal/bundles/format"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// Bundle publisher keys (G0 M37 D1084, D1084a, D1084b; HR-803). A
// publisher's private key is created and used only on the publisher's
// machine, like an org package-signing key: create writes it to a new file
// (mode 0600, encrypted with a passphrase when one is given) and a .pub file
// holding the public JWK; nothing here sends a private key anywhere.

func init() {
	for k, v := range publisherCommands() {
		commands[k] = v
	}
}

func publisherCommands() map[string]command {
	return map[string]command{
		"publisher key create": {"publisher key create --publisher ID --out FILE [--passphrase-file FILE]", createPublisherKey},
		"publisher pin":        {"publisher pin --publisher ID --key-file FILE.pub [--fingerprint HEX] [--allowed-kind KIND]... [--revocations-url URL]", pinPublisherKey},
	}
}

// pinPublisherKey creates a PENDING pin of a publisher's key (D1081,
// D1084b) and prints the page where a person activates it with a security
// key. The pin trusts nothing until then (HR-795).
func pinPublisherKey(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("publisher pin", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	publisher := fs.String("publisher", "", "publisher id")
	keyFile := fs.String("key-file", "", "the publisher's .pub file")
	fingerprint := fs.String("fingerprint", "", "the fingerprint the publisher announced (hex SHA-256); refused if the key differs")
	var kinds list
	fs.Var(&kinds, "allowed-kind", "an item kind the pin allows (repeatable; default: every kind)")
	revURL := fs.String("revocations-url", "", "https URL where the publisher posts signed revocation statements")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *publisher == "" {
		return errUsage
	}
	if *keyFile == "" {
		if *fingerprint != "" {
			return errors.New("a fingerprint alone cannot pin a key: give --key-file FILE.pub, and --fingerprint to check that file")
		}
		return errUsage
	}
	pub, keyPublisher, err := loadPublisherKey(*keyFile, *fingerprint)
	if err != nil {
		return err
	}
	if keyPublisher != *publisher {
		return fmt.Errorf("%s is a key of publisher %s, not %s", *keyFile, keyPublisher, *publisher)
	}
	for _, k := range kinds {
		if !format.Kind(k).Valid() {
			return fmt.Errorf("--allowed-kind %q is not an item kind", k)
		}
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewBundleServiceClient(s.connect()).PinPublisherKey(ctx, &pantherclawv1.PinPublisherKeyRequest{
		Publisher: *publisher, PublicKey: pub, AllowedKinds: kinds, RevocationsUrl: *revURL,
		ExpectedFingerprint: format.Fingerprint(pub),
	})
	if err != nil {
		return err
	}
	if err := a.print(res); err != nil {
		return err
	}
	if u := res.GetPin().GetConfirmUrl(); u != "" {
		_, _ = fmt.Fprintf(a.stderr, "The pin is PENDING and trusts nothing yet. A person with publisher.manage activates it with a security key at:\n  %s\n", u)
	}
	return nil
}

// maxPubFileBytes bounds a .pub file.
const maxPubFileBytes = 4 << 10

// createPublisherKey generates a publisher signing key on this machine.
func createPublisherKey(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("publisher key create", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	publisher := fs.String("publisher", "", "publisher id (^[a-z][a-z0-9-]{2,31}$)")
	out := fs.String("out", "", "new private key file; the public key goes to FILE.pub")
	ppFile := fs.String("passphrase-file", "", fmt.Sprintf("file holding a passphrase (at least %d characters) to encrypt the private key", rootkey.MinPassphrase))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	if !format.ValidPublisher(*publisher) {
		return errors.New("--publisher must match ^[a-z][a-z0-9-]{2,31}$")
	}
	pp, err := readPassphrase(*ppFile)
	if err != nil {
		return err
	}
	priv, _, err := rootkey.Generate(rootkey.PurposePublisher)
	if err != nil {
		return err
	}
	privPEM, err := rootkey.Encode(rootkey.PurposePublisher, priv, pp)
	if err != nil {
		return err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	kid := format.KID(*publisher, pub)
	jwk, err := json.Marshal(jws.PublicJWK(pub, kid))
	if err != nil {
		return err
	}
	pubPath := *out + ".pub"
	if _, err := os.Lstat(pubPath); err == nil {
		return fmt.Errorf("%s already exists", pubPath)
	}
	if err := rootkey.WriteNew(*out, privPEM); err != nil {
		return err
	}
	if err := rootkey.WriteNew(pubPath, append(jwk, '\n')); err != nil {
		return err
	}
	encrypted := "UNENCRYPTED: keep it on encrypted storage"
	if len(pp) > 0 {
		encrypted = "encrypted with your passphrase"
	}
	_, _ = fmt.Fprintf(a.stdout, "Created publisher key %s\n  fingerprint: %s\n  private key: %s (%s)\n  public key:  %s\n\n",
		kid, format.Fingerprint(pub), *out, encrypted, pubPath)
	_, _ = fmt.Fprintf(a.stdout, "Keep the private key offline. Publish the fingerprint where orgs already trust you, and give them %s;\nan org pins it with: pclaw publisher pin --publisher %s --key-file %s --fingerprint %s\n",
		pubPath, *publisher, pubPath, format.Fingerprint(pub))
	return nil
}

// loadPublisherKey reads a .pub file (a public JWK whose kid is a publisher
// key id) and returns the key and its publisher. When fingerprint is set,
// the key's fingerprint must equal it (D1084b).
func loadPublisherKey(path, fingerprint string) (ed25519.PublicKey, string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: user-chosen key file
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxPubFileBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > maxPubFileBytes {
		return nil, "", fmt.Errorf("%s is larger than %d bytes", path, maxPubFileBytes)
	}
	var j jws.JWK
	if err := json.Unmarshal(raw, &j, json.RejectUnknownMembers(true)); err != nil {
		return nil, "", fmt.Errorf("%s: not a public key file: %w", path, err)
	}
	pub, err := j.Key()
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	publisher, ok := format.KIDPublisher(j.Kid)
	if !ok || format.KID(publisher, pub) != j.Kid {
		return nil, "", fmt.Errorf("%s: kid %q is not this key's publisher key id", path, j.Kid)
	}
	if fingerprint != "" && strings.ToLower(strings.TrimSpace(fingerprint)) != format.Fingerprint(pub) {
		return nil, "", fmt.Errorf("%s: the key's fingerprint is %s, not %s", path, format.Fingerprint(pub), fingerprint)
	}
	return pub, publisher, nil
}
