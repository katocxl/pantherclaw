// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package admincli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// maxHubDays is the longest an index may run (D100).
const maxHubDays = int(domain.MaxValidity / (24 * time.Hour))

// hubBuild turns the Hub source tree into the static directory that is
// published: index.jws, signed offline, and items/<sha256>.json (G0 M23 D106).
func hubBuild(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("hub build", stderr)
	dir := fs.String("dir", "hub", "Hub source directory")
	out := fs.String("out", "", "new directory for index.jws and items/")
	keyFile := fs.String("key", "", "Hub root or development Hub private key file")
	ppFile := fs.String("passphrase-file", "", "file holding the key's passphrase")
	version := fs.Uint64("version", 0, "index version; must rise with every index published")
	days := fs.Int("expires-days", maxHubDays, "days until the index expires")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *keyFile == "" || *version < 1 || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	if *days < 1 || *days > maxHubDays {
		return fmt.Errorf("--expires-days must be between 1 and %d", maxHubDays)
	}
	signer, err := loadSigner(*keyFile, *ppFile, rootkey.PurposeHub, rootkey.PurposeDevHub)
	if err != nil {
		return err
	}
	items, err := seed.Load(os.DirFS(*dir))
	if err != nil {
		return err
	}
	at := now().UTC().Truncate(time.Second)
	x := domain.Index{
		Version: *version, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.AddDate(0, 0, *days).Format(time.RFC3339),
		Items: make([]domain.Entry, 0, len(items)),
	}
	for _, it := range items {
		x.Items = append(x.Items, it.Entry)
	}
	doc, err := domain.Sign(x, signer)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(*out, "items"), 0o750); err != nil {
		return err
	}
	for _, it := range items {
		path := filepath.Join(*out, "items", it.Entry.SHA256+".json")
		have, err := os.ReadFile(path) //nolint:gosec // G304: a digest under the operator's --out directory
		if err == nil && bytes.Equal(have, it.Raw) {
			continue
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := rootkey.WriteNew(path, it.Raw); err != nil {
			return err
		}
	}
	if err := rootkey.WriteNew(filepath.Join(*out, "index.jws"), []byte(doc+"\n")); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Built Hub index version %d with %s, %d items, expires %s → %s\n", x.Version, signer.KeyID(), len(items), x.ExpiresAt, *out)
	if domain.IsDevKID(signer.KeyID()) {
		_, _ = fmt.Fprint(stdout, "This is the development Hub key: only a local server with dev.hub_key_file trusts it.\n")
	}
	_, _ = fmt.Fprintf(stdout, "Build the next index with --version %d or higher: an older version, or another index under the same one, is refused.\n", x.Version+1)
	return nil
}
