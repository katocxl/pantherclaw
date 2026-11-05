// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/bundles/format"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/rootkey"
)

// Bundles offline (G0 M37 D1084, D1084a, D1084b; HR-797, HR-803). Every
// command here only reads, hashes, zips and signs bundle content with the
// decoders the server uses (internal/bundles/format). Nothing in a bundle is
// executed, no symlink is followed, and nothing is written except the named
// output. No command here contacts a server.

func init() {
	for k, v := range bundleCommands() {
		commands[k] = v
	}
}

func bundleCommands() map[string]command {
	return map[string]command{
		"bundle init":    {"bundle init --publisher ID --name ext.ID.SLUG DIR", bundleInit},
		"bundle lint":    {"bundle lint DIR|FILE.pcbundle", bundleLint},
		"bundle build":   {"bundle build DIR --out FILE.pcbundle", bundleBuild},
		"bundle sign":    {"bundle sign FILE.pcbundle --key FILE [--passphrase-file FILE] [--expires-days N] [--out FILE]", bundleSign},
		"bundle verify":  {"bundle verify FILE.pcbundle --public-key FILE.pub [--fingerprint HEX]", bundleVerify},
		"bundle inspect": {"bundle inspect FILE.pcbundle", bundleInspect},
	}
}

const (
	// defaultSignDays and the 400-day bound (format.MaxValidity) limit how
	// long a bundle signature stays valid.
	defaultSignDays = 365
	maxSignDays     = 400
	// unsignedMarker stands in for bundle.jws when an unsigned bundle is
	// decoded for lint; it is never written to a file.
	unsignedMarker = "unsigned"
)

// zipTime is the fixed modification time of every entry pclaw writes, so a
// build of the same directory gives the same bytes.
var zipTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// parseOneArg parses flags that may come before or after one positional
// argument and returns that argument.
func parseOneArg(fs *flag.FlagSet, args []string) (string, error) {
	var pos string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if pos == "" && fs.NArg() == 1 {
		return fs.Arg(0), nil
	}
	if pos == "" || fs.NArg() != 0 {
		return "", errUsage
	}
	return pos, nil
}

// bundleInit lays out a new bundle directory: bundle.json and items/.
func bundleInit(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("bundle init", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	publisher := fs.String("publisher", "", "publisher id")
	name := fs.String("name", "", "bundle name, ext.<publisher>.<slug>")
	dir, err := parseOneArg(fs, args)
	if err != nil {
		return err
	}
	if !format.ValidPublisher(*publisher) || !format.ValidBundleName(*publisher, *name) {
		return fmt.Errorf("--publisher must match ^[a-z][a-z0-9-]{2,31}$ and --name be ext.%s.<slug>", *publisher)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(dir, format.ItemsDir), 0o750); err != nil {
		return err
	}
	m := format.Manifest{Spec: format.Spec, Publisher: *publisher, Name: *name, Version: "0.1.0", Title: *name, Items: []format.ManifestItem{}}
	b, err := json.Marshal(m, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(filepath.Join(dir, format.ManifestFile), append(b, '\n')); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stdout, "Created %s. Put each item at items/<kind>/<file>, list it in bundle.json with its kind, name (ext.%s.…) and path, then:\n  pclaw bundle lint %s\n  pclaw bundle build %s --out %s-0.1.0.pcbundle\n",
		filepath.Join(dir, format.ManifestFile), *publisher, dir, dir, *name)
	return nil
}

// assembleDir reads a bundle directory: bundle.json with each item's sha256
// and size filled in from its file, and the item files. Item files must be
// regular files under items/<kind>/; a symlink is refused, never followed.
func assembleDir(dir string) ([]byte, map[string][]byte, error) {
	raw, err := readRegular(filepath.Join(dir, format.ManifestFile), format.MaxManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	var m format.Manifest
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, fmt.Errorf("bundle.json: %w", err)
	}
	files := map[string][]byte{}
	var total int64
	for i := range m.Items {
		it := &m.Items[i]
		p := it.Path
		if p == "" || path.Clean(p) != p || !strings.HasPrefix(p, format.ItemsDir+"/") || strings.Contains(p, "..") || strings.ContainsAny(p, "\\\x00") {
			return nil, nil, fmt.Errorf("item %q: path %q must be items/<kind>/<file>", it.Name, p)
		}
		if _, dup := files[p]; dup {
			return nil, nil, fmt.Errorf("item %q: %q appears twice", it.Name, p)
		}
		data, err := readRegular(filepath.Join(dir, filepath.FromSlash(p)), format.MaxItemBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("item %q: %w", it.Name, err)
		}
		total += int64(len(data))
		if total > format.MaxBundleBytes {
			return nil, nil, fmt.Errorf("the items exceed %d bytes", format.MaxBundleBytes)
		}
		sum := sha256.Sum256(data)
		it.SHA256, it.Size = hex.EncodeToString(sum[:]), int64(len(data))
		files[p] = data
	}
	manifest, err := json.Marshal(m, jsontext.WithIndent("  "))
	if err != nil {
		return nil, nil, err
	}
	manifest = append(manifest, '\n')
	if _, err := format.DecodeManifest(manifest); err != nil {
		return nil, nil, err
	}
	return manifest, files, nil
}

// readRegular reads a regular file of at most limit bytes; a symlink,
// device or directory is refused.
func readRegular(p string, limit int64) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, at most %d", p, st.Size(), limit)
	}
	f, err := os.Open(p) //nolint:gosec // G304: user-chosen bundle file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, limit)
	}
	return b, nil
}

// writeZip zips bundle.json, the items (in manifest order) and, when sig
// is set, bundle.jws, with fixed times and mode 0644.
func writeZip(manifest []byte, items map[string][]byte, order []string, sig string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: zipTime}
		h.SetMode(0o644)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	if err := add(format.ManifestFile, manifest); err != nil {
		return nil, err
	}
	if sig != "" {
		if err := add(format.SignatureFile, []byte(sig+"\n")); err != nil {
			return nil, err
		}
	}
	for _, p := range order {
		if err := add(p, items[p]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// withSignature returns a copy of the zip in raw with its bundle.jws
// replaced by sig. The other entries are copied with their headers, so
// Decode still sees their modes and methods.
func withSignature(raw []byte, sig string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("not a zip: %w", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		if f.Name == format.SignatureFile {
			continue
		}
		if err := zw.Copy(f); err != nil {
			return nil, err
		}
	}
	h := &zip.FileHeader{Name: format.SignatureFile, Method: zip.Deflate, Modified: zipTime}
	h.SetMode(0o644)
	w, err := zw.CreateHeader(h)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write([]byte(sig + "\n")); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// hasSignature reports whether the zip in raw holds bundle.jws.
func hasSignature(raw []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name == format.SignatureFile {
			return true
		}
	}
	return false
}

// decodeAny decodes a .pcbundle file, signed or not: an unsigned build is
// decoded with a stand-in signature, which Verify would refuse.
func decodeAny(raw []byte) (format.Bundle, bool, error) {
	if hasSignature(raw) {
		b, err := format.Decode(raw)
		return b, true, err
	}
	z, err := withSignature(raw, unsignedMarker)
	if err != nil {
		return format.Bundle{}, false, err
	}
	b, err := format.Decode(z)
	if err == nil {
		sum := sha256.Sum256(raw)
		b.SHA256, b.Signature = hex.EncodeToString(sum[:]), ""
	}
	return b, false, err
}

// bundleLint decodes a bundle directory or file with the server's decoders.
func bundleLint(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("bundle lint", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	target, err := parseOneArg(fs, args)
	if err != nil {
		return err
	}
	st, err := os.Lstat(target)
	if err != nil {
		return err
	}
	var b format.Bundle
	if st.IsDir() {
		manifest, files, err := assembleDir(target)
		if err != nil {
			return err
		}
		m, _ := format.DecodeManifest(manifest)
		order := make([]string, 0, len(m.Items))
		for _, it := range m.Items {
			order = append(order, it.Path)
		}
		z, err := writeZip(manifest, files, order, unsignedMarker)
		if err != nil {
			return err
		}
		if b, err = format.Decode(z); err != nil {
			return err
		}
	} else {
		raw, err := readRegular(target, format.MaxBundleBytes)
		if err != nil {
			return err
		}
		if b, _, err = decodeAny(raw); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(a.stdout, "%s@%s: %d items decode as their kinds (nothing was executed). Lint does not check a signature.\n",
		b.Manifest.Name, b.Manifest.Version, len(b.Items))
	return nil
}

// bundleBuild zips a bundle directory, filling each item's sha256 and size
// into bundle.json. The result is unsigned; bundle sign adds bundle.jws.
func bundleBuild(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("bundle build", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out := fs.String("out", "", "new .pcbundle file")
	dir, err := parseOneArg(fs, args)
	if err != nil {
		return err
	}
	if *out == "" {
		return errUsage
	}
	manifest, files, err := assembleDir(dir)
	if err != nil {
		return err
	}
	m, _ := format.DecodeManifest(manifest)
	order := make([]string, 0, len(m.Items))
	for _, it := range m.Items {
		order = append(order, it.Path)
	}
	check, err := writeZip(manifest, files, order, unsignedMarker)
	if err != nil {
		return err
	}
	if _, err := format.Decode(check); err != nil {
		return err
	}
	z, err := writeZip(manifest, files, order, "")
	if err != nil {
		return err
	}
	if err := rootkey.WriteNew(*out, z); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stdout, "Built %s (%s@%s, %d items, unsigned). Sign it with:\n  pclaw bundle sign %s --key FILE\n", *out, m.Name, m.Version, len(m.Items), *out)
	return nil
}

// bundleSign adds bundle.jws, signed with a publisher key, to a built
// bundle, then decodes and verifies the result with that key.
func bundleSign(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("bundle sign", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	keyFile := fs.String("key", "", "publisher private key file (publisher key create)")
	ppFile := fs.String("passphrase-file", "", "passphrase file for an encrypted key")
	days := fs.Int("expires-days", defaultSignDays, fmt.Sprintf("days until the signature expires, 1..%d", maxSignDays))
	out := fs.String("out", "", "new signed file (default: replace FILE)")
	file, err := parseOneArg(fs, args)
	if err != nil {
		return err
	}
	if *keyFile == "" || *days < 1 || *days > maxSignDays {
		return errUsage
	}
	raw, err := readRegular(file, format.MaxBundleBytes)
	if err != nil {
		return err
	}
	b, _, err := decodeAny(raw)
	if err != nil {
		return err
	}
	pp, err := readPassphrase(*ppFile)
	if err != nil {
		return err
	}
	keyPEM, err := readRegular(*keyFile, 64<<10)
	if err != nil {
		return err
	}
	p, priv, err := rootkey.Decode(keyPEM, pp)
	if err != nil {
		return err
	}
	if p != rootkey.PurposePublisher {
		return fmt.Errorf("%s is a %s key, not a publisher key", *keyFile, p)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	kid := format.KID(b.Manifest.Publisher, pub)
	signer, err := jws.NewSigner(kid, priv)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	sig, err := format.Sign(signer, b.ManifestBytes, now, now.AddDate(0, 0, *days))
	if err != nil {
		return err
	}
	signed, err := withSignature(raw, sig)
	if err != nil {
		return err
	}
	sb, err := format.Decode(signed)
	if err != nil {
		return err
	}
	pin := format.PinnedKey{Publisher: b.Manifest.Publisher, KID: kid, PublicKey: pub}
	if err := format.Verify(sb, []format.PinnedKey{pin}, now); err != nil {
		return err
	}
	if *out != "" {
		if err := rootkey.WriteNew(*out, signed); err != nil {
			return err
		}
	} else if err := replaceFile(file, signed); err != nil {
		return err
	}
	dest := file
	if *out != "" {
		dest = *out
	}
	_, _ = fmt.Fprintf(a.stdout, "Signed %s@%s with %s (fingerprint %s), valid for %d days → %s\n  sha256 %s\n",
		sb.Manifest.Name, sb.Manifest.Version, kid, format.Fingerprint(pub), *days, dest, sb.SHA256)
	return nil
}

// replaceFile writes data to a new file next to p and renames it over p.
func replaceFile(p string, data []byte) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", p)
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".pcbundle-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// bundleVerify checks a signed bundle against a publisher's public key file
// and, optionally, the fingerprint the publisher announced (D1084b).
func bundleVerify(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("bundle verify", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	keyFile := fs.String("public-key", "", "the publisher's .pub file")
	fingerprint := fs.String("fingerprint", "", "the fingerprint the publisher announced (hex SHA-256); checked against the key file")
	file, err := parseOneArg(fs, args)
	if err != nil {
		return err
	}
	if *keyFile == "" {
		if *fingerprint != "" {
			return errors.New("a fingerprint alone cannot check a signature: give --public-key FILE.pub, and --fingerprint to check that file")
		}
		return errUsage
	}
	pub, publisher, err := loadPublisherKey(*keyFile, *fingerprint)
	if err != nil {
		return err
	}
	raw, err := readRegular(file, format.MaxBundleBytes)
	if err != nil {
		return err
	}
	b, err := format.Decode(raw)
	if err != nil {
		return err
	}
	if publisher != b.Manifest.Publisher {
		return fmt.Errorf("the key belongs to publisher %s; the bundle is %s's", publisher, b.Manifest.Publisher)
	}
	kid := format.KID(publisher, pub)
	if err := format.Verify(b, []format.PinnedKey{{Publisher: publisher, KID: kid, PublicKey: pub}}, time.Now()); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stdout, "%s@%s: the signature verifies with %s (fingerprint %s); %d items match their digests.\n  sha256 %s\nThis checks who signed the bundle, not what it does: an install still lands as drafts for your org to review.\n",
		b.Manifest.Name, b.Manifest.Version, kid, format.Fingerprint(pub), len(b.Items), b.SHA256)
	return nil
}

// bundleInspect prints a bundle's manifest, digest and signature claims,
// without verifying the signature.
func bundleInspect(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("bundle inspect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	file, err := parseOneArg(fs, args)
	if err != nil {
		return err
	}
	raw, err := readRegular(file, format.MaxBundleBytes)
	if err != nil {
		return err
	}
	b, signed, err := decodeAny(raw)
	if err != nil {
		return err
	}
	type inspected struct {
		SHA256    string          `json:"sha256"`
		Manifest  format.Manifest `json:"manifest"`
		Signed    bool            `json:"signed"`
		KID       string          `json:"kid,omitzero"`
		Claims    jsontext.Value  `json:"claims_unverified,omitzero"`
		VerifyCmd string          `json:"verify_with,omitzero"`
	}
	out := inspected{SHA256: b.SHA256, Manifest: b.Manifest, Signed: signed}
	if signed {
		kid, _, err := jws.Unverified(b.Signature)
		if err != nil {
			return err
		}
		out.KID = kid
		if parts := strings.Split(b.Signature, "."); len(parts) == 3 {
			if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil && jsontext.Value(payload).IsValid() {
				out.Claims = jsontext.Value(payload)
			}
		}
		out.VerifyCmd = "pclaw bundle verify " + file + " --public-key FILE.pub --fingerprint HEX"
	}
	j, err := json.Marshal(out, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.stdout, string(j))
	return err
}
