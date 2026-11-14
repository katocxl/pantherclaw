// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command marketplace renders the static PantherClaw marketplace (G0 M37
// D1085, HR-802): plain HTML and CSS, no JavaScript, from the Hub build
// directory and the publisher listings in marketplace/listings.
//
// A listing is not an endorsement. The marketplace only lists: it takes no
// payment, has no install action, and every page says that installing a
// publisher's bundle needs the org to pin that publisher's key first
// (FQ37-1). It shows digests, key fingerprints and the pclaw commands to
// copy. It imports nothing from internal/ (the tools module cannot), so the
// Hub index is read as plain JSON and is not verified here; pclaw verifies
// what it installs.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

//go:embed assets/*
var assets embed.FS

// Bounds on what a listing and the Hub directory may hold.
const (
	maxListingBytes = 256 << 10
	maxIndexBytes   = 1 << 20
	maxItemBytes    = 1 << 20
	maxBundles      = 200
	maxKeys         = 16
	maxSummaryBytes = 500
	maxDisplayBytes = 80
	maxNameBytes    = 128
)

var (
	publisherID = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)
	hexDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// version and slug mirror internal/bundles/format (MAJOR.MINOR.PATCH;
	// ext.<publisher>.<slug>), which the tools module cannot import.
	version = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	slug    = `[a-z0-9][a-z0-9-]{0,62}`
	hubName = regexp.MustCompile(`^pc\.[a-z0-9-]+(\.[a-z0-9-]+)*$`)
)

// Listing is marketplace/listings/<publisher>.json, written by the
// publisher and submitted for review (D1085, D1084b).
type Listing struct {
	Publisher   string         `json:"publisher"`
	DisplayName string         `json:"display_name"`
	Homepage    string         `json:"homepage"`
	Keys        []ListedKey    `json:"keys"`
	Bundles     []ListedBundle `json:"bundles"`
}

// ListedKey is one publisher key, inline: the base64url raw Ed25519 public
// key and its fingerprint (the hex SHA-256 of the raw key), which must match
// (D1084b). PubFile and KID are filled in by the build.
type ListedKey struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	PubFile     string `json:"-"`
	KID         string `json:"-"`
	jwk         []byte
}

// ListedBundle is one bundle a listing points at.
type ListedBundle struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Summary string `json:"summary"`
}

// hubEntry is one entry of the Hub index payload.
type hubEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

type hubIndex struct {
	Spec      string     `json:"spec"`
	Version   uint64     `json:"version"`
	IssuedAt  string     `json:"issued_at"`
	ExpiresAt string     `json:"expires_at"`
	Items     []hubEntry `json:"items"`
}

func main() {
	root := flag.String("root", "..", "repository root")
	hub := flag.String("hub", "", "a Hub build directory (index.jws and items/); empty lists no Hub items")
	out := flag.String("out", "../dist/marketplace", "new, empty output directory")
	flag.Parse()
	if flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := build(*root, *hub, *out); err != nil {
		fmt.Fprintln(os.Stderr, "marketplace:", err)
		os.Exit(1)
	}
}

func build(root, hubDir, out string) error {
	listings, err := readListings(filepath.Join(root, "marketplace", "listings"))
	if err != nil {
		return err
	}
	var index *hubIndex
	if hubDir != "" {
		if index, err = readHub(hubDir); err != nil {
			return err
		}
	}
	if err := emptyDir(out); err != nil {
		return err
	}
	tmpl, err := template.ParseFS(assets, "assets/*.tmpl")
	if err != nil {
		return err
	}
	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "style.css"), css, 0o600); err != nil {
		return err
	}
	if err := render(tmpl, "index.html.tmpl", filepath.Join(out, "index.html"), map[string]any{
		"Prefix": "", "Listings": listings, "Hub": index,
	}); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(out, "publishers"), 0o750); err != nil {
		return err
	}
	for _, l := range listings {
		for _, k := range l.Keys {
			if err := os.WriteFile(filepath.Join(out, "publishers", k.PubFile), k.jwk, 0o600); err != nil {
				return err
			}
		}
		if err := render(tmpl, "publisher.html.tmpl", filepath.Join(out, "publishers", l.Publisher+".html"), map[string]any{
			"Prefix": "../", "L": l,
		}); err != nil {
			return err
		}
	}
	return nil
}

// emptyDir creates out, refusing one that already holds files, so a stale
// page never survives a build.
func emptyDir(out string) error {
	entries, err := os.ReadDir(out)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(out, 0o750)
	case err != nil:
		return err
	case len(entries) != 0:
		return fmt.Errorf("%s is not empty; remove it first", out)
	}
	return nil
}

func render(t *template.Template, name, path string, data any) error {
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, name, data); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o600)
}

func readListings(dir string) ([]Listing, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Listing
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s: not a regular file", e.Name())
		}
		l, err := readListing(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if l.Publisher+".json" != e.Name() {
			return nil, fmt.Errorf("%s: the file must be named %s.json", e.Name(), l.Publisher)
		}
		out = append(out, l)
	}
	slices.SortFunc(out, func(a, b Listing) int { return strings.Compare(a.Publisher, b.Publisher) })
	return out, nil
}

func readListing(path string) (Listing, error) {
	b, err := readBounded(path, maxListingBytes)
	if err != nil {
		return Listing{}, err
	}
	var l Listing
	if err := json.Unmarshal(b, &l, json.RejectUnknownMembers(true)); err != nil {
		return Listing{}, err
	}
	if err := l.check(); err != nil {
		return Listing{}, err
	}
	for i := range l.Keys {
		k := &l.Keys[i]
		thumb := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + k.PublicKey + `"}`))
		k.KID = "publisher-" + l.Publisher + "-" + base64.RawURLEncoding.EncodeToString(thumb[:])[:22]
		k.PubFile = l.Publisher + "-" + k.Fingerprint[:16] + ".pub"
		jwk, err := json.Marshal(publicJWK{Kty: "OKP", Crv: "Ed25519", X: k.PublicKey, Kid: k.KID, Alg: "EdDSA", Use: "sig"})
		if err != nil {
			return Listing{}, err
		}
		jwk = append(jwk, '\n')
		k.jwk = jwk
	}
	return l, nil
}

// publicJWK is the .pub file pclaw publisher key create writes: the
// public JWK of the key, with its publisher kid (format.KID).
type publicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// check refuses a listing that is malformed. It proves nothing about the
// publisher: the org pins the key itself (FQ37-1, T-364).
func (l Listing) check() error {
	if !publisherID.MatchString(l.Publisher) {
		return fmt.Errorf("publisher %q must match %s", l.Publisher, publisherID)
	}
	if err := text("display_name", l.DisplayName, maxDisplayBytes); err != nil {
		return err
	}
	if err := httpsURL("homepage", l.Homepage); err != nil {
		return err
	}
	if len(l.Keys) == 0 || len(l.Keys) > maxKeys {
		return fmt.Errorf("keys: 1 to %d needed", maxKeys)
	}
	for _, k := range l.Keys {
		if !hexDigest.MatchString(k.Fingerprint) {
			return fmt.Errorf("key fingerprint %q must be a lowercase hex SHA-256", k.Fingerprint)
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("key %s: public_key must be the base64url raw 32-byte Ed25519 key", k.Fingerprint)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != k.Fingerprint {
			return fmt.Errorf("key %s: the fingerprint does not match the public key", k.Fingerprint)
		}
	}
	if len(l.Bundles) > maxBundles {
		return fmt.Errorf("at most %d bundles", maxBundles)
	}
	name := regexp.MustCompile(`^ext\.` + regexp.QuoteMeta(l.Publisher) + `\.` + slug + `$`)
	seen := map[string]bool{}
	for _, b := range l.Bundles {
		if len(b.Name) > maxNameBytes || !name.MatchString(b.Name) {
			return fmt.Errorf("bundle %q must be named ext.%s.<name>", b.Name, l.Publisher)
		}
		if !version.MatchString(b.Version) {
			return fmt.Errorf("bundle %s: version %q is not MAJOR.MINOR.PATCH", b.Name, b.Version)
		}
		if seen[b.Name+"@"+b.Version] {
			return fmt.Errorf("bundle %s@%s is listed twice", b.Name, b.Version)
		}
		seen[b.Name+"@"+b.Version] = true
		if err := httpsURL("bundle url", b.URL); err != nil {
			return err
		}
		if !hexDigest.MatchString(b.SHA256) {
			return fmt.Errorf("bundle %s: sha256 must be lowercase hex", b.Name)
		}
		if err := text("summary", b.Summary, maxSummaryBytes); err != nil {
			return err
		}
	}
	return nil
}

func text(field, s string, limit int) error {
	if s == "" || len(s) > limit || !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s: 1 to %d bytes of plain text", field, limit)
	}
	return nil
}

func httpsURL(field, s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(s) > 2048 {
		return fmt.Errorf("%s %q must be an https URL without credentials", field, s)
	}
	return nil
}

// readHub reads a Hub build directory: the payload of index.jws as plain
// JSON, and each item file, whose SHA-256 must match its entry.
func readHub(dir string) (*hubIndex, error) {
	b, err := readBounded(filepath.Join(dir, "index.jws"), maxIndexBytes)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(string(b)), ".")
	if len(parts) != 3 {
		return nil, errors.New("index.jws is not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("index.jws payload: %w", err)
	}
	var idx hubIndex
	if err := json.Unmarshal(payload, &idx); err != nil {
		return nil, fmt.Errorf("index.jws payload: %w", err)
	}
	for _, e := range idx.Items {
		if !hubName.MatchString(e.Name) || !hexDigest.MatchString(e.SHA256) {
			return nil, fmt.Errorf("hub entry %q: bad name or digest", e.Name)
		}
		item, err := readBounded(filepath.Join(dir, "items", e.SHA256+".json"), maxItemBytes)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(item)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, fmt.Errorf("hub item %s@%s: the file does not match its digest", e.Name, e.Version)
		}
	}
	slices.SortFunc(idx.Items, func(a, b hubEntry) int {
		return strings.Compare(a.Kind+" "+a.Name, b.Kind+" "+b.Name)
	})
	return &idx, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return os.ReadFile(path) //nolint:gosec // The caller names the repository and Hub directories.
}
