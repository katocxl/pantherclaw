// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package admincli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// maxIntelDays is the longest a feed may run (D1103).
const maxIntelDays = int(domain.MaxValidity / (24 * time.Hour))

// intelSource is the feed maintainer's indicator file: hashes only.
type intelSource struct {
	Indicators []domain.Indicator `json:"indicators"`
}

// intelBuild signs a shared threat-intel feed offline (G0 M38 D1103): the
// indicators in --in, under --version, with the intel root or the
// development intel key. The server imports the file with
// `pantherclaw-server intel import`, or fetches it from intel.feed_url.
func intelBuild(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("intel build", stderr)
	in := fs.String("in", "", "JSON file {\"indicators\": [...]}: hashes only")
	out := fs.String("out", "", "new file for the signed feed")
	keyFile := fs.String("key", "", "intel root or development intel private key file")
	ppFile := fs.String("passphrase-file", "", "file holding the key's passphrase")
	version := fs.Uint64("version", 0, "feed version; must rise with every feed published")
	days := fs.Int("expires-days", maxIntelDays, "days until the feed expires")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" || *keyFile == "" || *version < 1 || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	if *days < 1 || *days > maxIntelDays {
		return fmt.Errorf("--expires-days must be between 1 and %d", maxIntelDays)
	}
	signer, err := loadSigner(*keyFile, *ppFile, rootkey.PurposeIntel, rootkey.PurposeDevIntel)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*in) //nolint:gosec // G304: operator-chosen input path
	if err != nil {
		return err
	}
	var src intelSource
	if err := json.Unmarshal(raw, &src, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	at := now().UTC().Truncate(time.Second)
	f := domain.Feed{
		Version: *version, Issued: at.Format(time.RFC3339), Expires: at.AddDate(0, 0, *days).Format(time.RFC3339),
		Indicators: src.Indicators,
	}
	if f.Indicators == nil {
		f.Indicators = []domain.Indicator{}
	}
	doc, err := domain.Sign(f, signer)
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(*out, []byte(doc+"\n")); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Built intel feed version %d with %s, %d indicators, expires %s → %s\n",
		f.Version, signer.KeyID(), len(f.Indicators), f.Expires, *out)
	if domain.IsDevKID(signer.KeyID()) {
		_, _ = fmt.Fprint(stdout, "This is the development intel key: only a local server with dev.intel_key_file trusts it.\n")
	}
	_, _ = fmt.Fprintf(stdout, "Build the next feed with --version %d or higher: an older version, or another feed under the same one, is refused.\n", f.Version+1)
	return nil
}

// intelVerify checks a signed feed against a roots file, offline.
func intelVerify(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	fs := newFlags("intel verify", stderr)
	rootsFile := fs.String("roots", "", "intel roots JWKS (or a development intel public key)")
	in := fs.String("in", "", "signed feed")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootsFile == "" || *in == "" || fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	rb, err := os.ReadFile(*rootsFile) //nolint:gosec // G304: operator-chosen roots path
	if err != nil {
		return err
	}
	roots, err := domain.ParseRoots(rb)
	if err != nil {
		if roots, err = domain.ParseDevKey(rb); err != nil {
			return err
		}
	}
	doc, err := os.ReadFile(*in) //nolint:gosec // G304: operator-chosen feed path
	if err != nil {
		return err
	}
	v, err := domain.Verify(string(doc), roots, now())
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Feed version %d verifies with %s: %d indicators, expires %s, payload sha256 %s\n",
		v.Version, v.KID, len(v.Indicators), v.Expires, v.Digest)
	return nil
}
