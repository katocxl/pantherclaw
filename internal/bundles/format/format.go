// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package format reads and checks pc-bundle/1 publisher bundles (G0 M37
// D1080; FQ37-1, FQ37-2; HR-796, HR-797, HR-801, HR-803).
//
// A bundle is one .pcbundle file, a zip holding:
//
//   - bundle.json, the manifest: spec "pc-bundle/1", the publisher, the
//     bundle's name (ext.<publisher>.<slug>) and version, a title, a summary
//     and the items, each {kind, name, path, sha256, size};
//   - bundle.jws, a compact JWS (EdDSA, typ pc-bundle+jwt, kid
//     publisher-<publisher>-<thumb22>) whose claims carry the SHA-256 of the
//     exact bundle.json bytes, the publisher, name and version, iat and exp
//     (at most 400 days after iat);
//   - the item files, at items/<kind>/<file>.
//
// Bundles are data only, never code. The item kinds are a closed list,
// each decoded strictly by its own decoder; nothing in a bundle is ever
// run, loaded as a plugin or executed, here or anywhere else. Decode reads
// and checks the file and every item; Verify checks the signature against
// the keys an org pinned. pclaw and the server use both.
//
// A "publisher" in this package is a bundle publisher (an organization
// that signs bundles), never a person.
package format

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defsdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/openapi"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
)

// Spec is the format's name and version.
const Spec = "pc-bundle/1"

// File names inside a bundle.
const (
	ManifestFile  = "bundle.json"
	SignatureFile = "bundle.jws"
	ItemsDir      = "items"
)

// Limits (D1080, D1080a).
const (
	// MaxItems bounds a bundle's items.
	MaxItems = 64
	// MaxFileBytes bounds the .pcbundle file itself, so that it fits one
	// API request (the 1 MiB request cap; D1080a). Chunked upload is a
	// follow-up.
	MaxFileBytes = 960 << 10
	// MaxItemBytes bounds one uncompressed item file (a zip-bomb limit).
	MaxItemBytes = 1 << 20
	// MaxBundleBytes bounds the sum of the uncompressed contents (a
	// zip-bomb limit).
	MaxBundleBytes = 8 << 20
	// MaxManifestBytes bounds bundle.json.
	MaxManifestBytes = 256 << 10
	// MaxTitle and MaxSummary bound the plain-text title and summary.
	MaxTitle   = 128
	MaxSummary = 1024
)

// Kind is an item kind. The list is closed (FQ37-2): data only.
type Kind string

// Item kinds.
const (
	// KindToolPackage is a tool package (package.yaml) decoded by
	// manifest.Decode; it may name an openapi_spec item whose data-driven
	// simulator serves it.
	KindToolPackage Kind = "tool_package"
	// KindOpenAPISpec is an OpenAPI 3 document a tool_package's simulator
	// names.
	KindOpenAPISpec Kind = "openapi_spec"
	// KindDetectionRule is a custom detection rule (YAML), id
	// ext.<publisher>.<name>.
	KindDetectionRule Kind = "detection_rule"
	// KindPlaybook is an automation definition (YAML), closed step catalog.
	KindPlaybook Kind = "playbook"
	// KindFactsDeclaration is a fact provider declaration: data only, with
	// no reader.
	KindFactsDeclaration Kind = "facts_declaration"
	// KindChannelTemplate is a notification channel template without any
	// secret.
	KindChannelTemplate Kind = "channel_template"
)

// Kinds returns every item kind in a stable order.
func Kinds() []Kind {
	return []Kind{KindToolPackage, KindOpenAPISpec, KindDetectionRule, KindPlaybook, KindFactsDeclaration, KindChannelTemplate}
}

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool { return slices.Contains(Kinds(), k) }

// extensions are the file extensions each kind's files may have.
var extensions = map[Kind][]string{
	KindToolPackage:      {".yaml", ".yml"},
	KindOpenAPISpec:      {".yaml", ".yml", ".json"},
	KindDetectionRule:    {".yaml", ".yml"},
	KindPlaybook:         {".yaml", ".yml", ".json"},
	KindFactsDeclaration: {".yaml", ".yml", ".json"},
	KindChannelTemplate:  {".yaml", ".yml", ".json"},
}

// SimulatorOpenAPI is the only simulator a bundle may name: the existing
// data-driven OpenAPI simulator (FQ37-2). Compiled simulators are never
// part of a bundle.
const SimulatorOpenAPI = "openapi"

// Error is a refusal of the format; Code is stable for callers and APIs.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return "bundle: " + e.Code + ": " + e.Msg }

// Is matches errors of the same code.
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Code == e.Code
}

// Errors. Each wraps one *Error; match with errors.Is.
var (
	ErrFormat        = &Error{"BUNDLE_FORMAT", "the file is not a pc-bundle/1 bundle"}
	ErrLimit         = &Error{"BUNDLE_LIMIT", "the bundle exceeds a limit: a 960 KiB file, 64 items, 1 MiB per item, 8 MiB uncompressed in total"}
	ErrPath          = &Error{"BUNDLE_PATH", "a bundle holds only bundle.json, bundle.jws and items/<kind>/<file> regular files"}
	ErrNamespace     = &Error{"BUNDLE_NAMESPACE", "every name in a bundle is ext.<publisher>.<name>, in its own publisher's namespace"}
	ErrKind          = &Error{"BUNDLE_KIND", "the item kind is not one a bundle may carry"}
	ErrExecutable    = &Error{"BUNDLE_EXECUTABLE", "bundles are data only: executables, scripts, WASM and binaries are refused"}
	ErrDigest        = &Error{"BUNDLE_DIGEST", "an item's size or SHA-256 differs from the manifest"}
	ErrItem          = &Error{"BUNDLE_ITEM", "an item does not decode strictly as its kind"}
	ErrSecret        = &Error{"BUNDLE_SECRET", "a channel template carries no secret"}
	ErrSimulator     = &Error{"BUNDLE_SIMULATOR", "the only simulator a bundle may name is openapi, over an openapi_spec item"}
	ErrSignature     = &Error{"BUNDLE_SIGNATURE", "the bundle's signature does not verify"}
	ErrUnpinned      = &Error{"PUBLISHER_NOT_PINNED", "no active pinned key of this publisher signed the bundle"}
	ErrKindNotPinned = &Error{"BUNDLE_KIND_NOT_ALLOWED", "the publisher's pinned key does not allow an item kind of this bundle"}
	ErrExpired       = &Error{"BUNDLE_SIGNATURE_EXPIRED", "the bundle's signature is expired or not yet valid"}
	ErrRevocation    = &Error{"REVOCATION_INVALID", "the revocation statement is not valid"}
)

func fail(e *Error, format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{e}, args...)...)
}

var (
	publisherRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)
	bundleNameRe = regexp.MustCompile(`^ext\.([a-z][a-z0-9-]{2,31})\.[a-z0-9][a-z0-9-]{0,62}$`)
	itemNameRe   = regexp.MustCompile(`^ext\.([a-z][a-z0-9-]{2,31})\.[a-z0-9]([a-z0-9._-]{0,94}[a-z0-9])?$`)
	versionRe    = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	fileRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidPublisher reports whether s is a publisher id.
func ValidPublisher(s string) bool { return publisherRe.MatchString(s) }

// ValidBundleName reports whether s is a bundle name of publisher.
func ValidBundleName(publisher, s string) bool {
	m := bundleNameRe.FindStringSubmatch(s)
	return m != nil && m[1] == publisher
}

// ValidVersion reports whether s is a MAJOR.MINOR.PATCH version.
func ValidVersion(s string) bool { return versionRe.MatchString(s) }

// CompareVersions compares two valid versions: -1, 0 or 1.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range 3 {
		if i >= len(pa) || i >= len(pb) {
			break
		}
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// itemPublisher returns the publisher of an item name.
func itemPublisher(name string) (string, bool) {
	m := itemNameRe.FindStringSubmatch(name)
	if m == nil || strings.Contains(name, "..") {
		return "", false
	}
	return m[1], true
}

// Simulator is a tool_package's optional simulator.
type Simulator struct {
	// Kind is always "openapi".
	Kind string `json:"kind"`
	// Spec is the path of an openapi_spec item of the same bundle.
	Spec string `json:"spec"`
}

// ManifestItem is one entry of bundle.json's items.
type ManifestItem struct {
	Kind   Kind   `json:"kind"`
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Simulator is allowed on a tool_package only.
	Simulator *Simulator `json:"simulator,omitzero"`
}

// Manifest is bundle.json.
type Manifest struct {
	Spec      string         `json:"spec"`
	Publisher string         `json:"publisher"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Title     string         `json:"title"`
	Summary   string         `json:"summary"`
	Items     []ManifestItem `json:"items"`
}

// Item is one decoded item. Exactly one of the decoded fields is set,
// for its kind.
type Item struct {
	ManifestItem
	// Data is the item file's exact bytes.
	Data []byte

	Package  *defsdomain.Package
	OpenAPI  *openapi.Spec
	Rule     *rules.Rule
	Playbook *autodomain.Definition
	Facts    *FactsDeclaration
	Channel  *ChannelTemplate
}

// Bundle is a decoded bundle. It is not trusted until Verify passes.
type Bundle struct {
	Manifest Manifest
	// ManifestBytes are bundle.json's exact bytes, which the signature
	// covers.
	ManifestBytes []byte
	// Signature is bundle.jws.
	Signature string
	// SHA256 is the hex SHA-256 of the whole .pcbundle file.
	SHA256 string
	Items  []Item
}

// Kinds returns the bundle's distinct item kinds.
func (b Bundle) Kinds() []Kind {
	var out []Kind
	for _, it := range b.Items {
		if !slices.Contains(out, it.Kind) {
			out = append(out, it.Kind)
		}
	}
	return out
}

// DecodeManifest decodes bundle.json strictly (unknown members and
// duplicate names refused) and checks it.
func DecodeManifest(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return m, fail(ErrLimit, "bundle.json is %d bytes, at most %d", len(raw), MaxManifestBytes)
	}
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
		return m, fail(ErrFormat, "bundle.json: %v", err)
	}
	return m, m.check()
}

// check validates the manifest by itself.
func (m Manifest) check() error {
	switch {
	case m.Spec != Spec:
		return fail(ErrFormat, "spec %q, want %q", m.Spec, Spec)
	case !ValidPublisher(m.Publisher):
		return fail(ErrNamespace, "publisher %q must match %s", m.Publisher, publisherRe)
	case !ValidBundleName(m.Publisher, m.Name):
		return fail(ErrNamespace, "bundle name %q must be ext.%s.<slug>", m.Name, m.Publisher)
	case !ValidVersion(m.Version):
		return fail(ErrFormat, "version %q must be MAJOR.MINOR.PATCH", m.Version)
	case !plainText(m.Title, MaxTitle) || strings.TrimSpace(m.Title) == "":
		return fail(ErrFormat, "title must be 1..%d bytes of plain text", MaxTitle)
	case !plainText(m.Summary, MaxSummary):
		return fail(ErrFormat, "summary must be at most %d bytes of plain text", MaxSummary)
	case len(m.Items) == 0 || len(m.Items) > MaxItems:
		return fail(ErrLimit, "a bundle has 1..%d items", MaxItems)
	}
	names, paths := map[string]bool{}, map[string]bool{}
	var total int64
	for _, it := range m.Items {
		if !it.Kind.Valid() {
			return fail(ErrKind, "%q", it.Kind)
		}
		pub, ok := itemPublisher(it.Name)
		if !ok || pub != m.Publisher {
			return fail(ErrNamespace, "item name %q must be ext.%s.<name>", it.Name, m.Publisher)
		}
		if names[it.Name] {
			return fail(ErrFormat, "item name %q appears twice", it.Name)
		}
		names[it.Name] = true
		if err := checkItemPath(it.Kind, it.Path); err != nil {
			return err
		}
		if paths[it.Path] {
			return fail(ErrPath, "%q appears twice", it.Path)
		}
		paths[it.Path] = true
		if !sha256Re.MatchString(it.SHA256) {
			return fail(ErrFormat, "item %q: sha256 must be 64 lowercase hex digits", it.Name)
		}
		if it.Size < 1 || it.Size > MaxItemBytes {
			return fail(ErrLimit, "item %q is %d bytes, 1..%d", it.Name, it.Size, MaxItemBytes)
		}
		total += it.Size
		if it.Simulator != nil {
			if it.Kind != KindToolPackage {
				return fail(ErrSimulator, "item %q: only a tool_package names a simulator", it.Name)
			}
			if it.Simulator.Kind != SimulatorOpenAPI {
				return fail(ErrSimulator, "item %q: simulator kind %q", it.Name, it.Simulator.Kind)
			}
		}
	}
	if total > MaxBundleBytes {
		return fail(ErrLimit, "the items total %d bytes, at most %d", total, MaxBundleBytes)
	}
	// Every simulator names an openapi_spec item; every openapi_spec item
	// is named by a simulator.
	specs := map[string]bool{}
	for _, it := range m.Items {
		if it.Kind == KindOpenAPISpec {
			specs[it.Path] = false
		}
	}
	for _, it := range m.Items {
		if it.Simulator == nil {
			continue
		}
		if _, ok := specs[it.Simulator.Spec]; !ok {
			return fail(ErrSimulator, "item %q: %q is not an openapi_spec item of this bundle", it.Name, it.Simulator.Spec)
		}
		specs[it.Simulator.Spec] = true
	}
	for p, used := range specs {
		if !used {
			return fail(ErrSimulator, "openapi_spec %q is not named by any tool_package simulator", p)
		}
	}
	return nil
}

// checkItemPath checks items/<kind>/<file>.
func checkItemPath(k Kind, p string) error {
	parts := strings.Split(p, "/")
	if len(parts) != 3 || parts[0] != ItemsDir || parts[1] != string(k) || !fileRe.MatchString(parts[2]) ||
		parts[2] == "." || parts[2] == ".." || strings.Contains(parts[2], "..") {
		return fail(ErrPath, "%q must be items/%s/<file>", p, k)
	}
	if !slices.Contains(extensions[k], strings.ToLower(path.Ext(parts[2]))) {
		return fail(ErrPath, "%q: a %s file ends in %s", p, k, strings.Join(extensions[k], ", "))
	}
	return nil
}

// plainText reports whether s is valid UTF-8 of at most n bytes without
// control, format or bidi characters (they reach terminals and pages).
func plainText(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// executableMagic are file prefixes of executables, binaries, archives and
// scripts. A data item never starts with one.
var executableMagic = [][]byte{
	[]byte("MZ"),               // PE
	[]byte("\x7fELF"),          // ELF
	[]byte("\x00asm"),          // WASM
	[]byte("#!"),               // script
	[]byte("\xfe\xed\xfa\xce"), // Mach-O
	[]byte("\xfe\xed\xfa\xcf"),
	[]byte("\xce\xfa\xed\xfe"),
	[]byte("\xcf\xfa\xed\xfe"),
	[]byte("\xca\xfe\xba\xbe"), // Mach-O universal, Java class
	[]byte("PK\x03\x04"),       // nested zip, jar
	[]byte("\x1f\x8b"),         // gzip
	[]byte("dex\n"),            // Android
}

// textOnly reports whether b is UTF-8 text without NUL or other control
// bytes than tab, LF and CR, and starts with no executable magic.
func textOnly(b []byte) bool {
	for _, m := range executableMagic {
		if bytes.HasPrefix(b, m) {
			return false
		}
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// Decode reads a .pcbundle file: the zip layout, the manifest, every item's
// size and digest, and every item decoded strictly as its kind. Nothing in
// it is executed. The result is not trusted until Verify passes.
func Decode(zipBytes []byte) (Bundle, error) {
	var b Bundle
	if len(zipBytes) == 0 || len(zipBytes) > MaxFileBytes {
		return b, fail(ErrLimit, "the file is %d bytes, 1..%d", len(zipBytes), MaxFileBytes)
	}
	sum := sha256.Sum256(zipBytes)
	b.SHA256 = hex.EncodeToString(sum[:])
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return b, fail(ErrFormat, "not a zip: %v", err)
	}
	if len(zr.File) > MaxItems+2+1+len(Kinds()) {
		return b, fail(ErrLimit, "%d entries", len(zr.File))
	}
	files := map[string][]byte{}
	var total int64
	for _, f := range zr.File {
		name := f.Name
		if err := checkEntry(f); err != nil {
			return b, err
		}
		if strings.HasSuffix(name, "/") {
			continue // a directory entry checkEntry allowed
		}
		if _, dup := files[name]; dup {
			return b, fail(ErrPath, "%q appears twice", name)
		}
		limit := int64(MaxItemBytes)
		switch name {
		case ManifestFile:
			limit = MaxManifestBytes
		case SignatureFile:
			limit = 64 << 10
		}
		if f.UncompressedSize64 > uint64(limit) {
			return b, fail(ErrLimit, "%q is %d bytes, at most %d", name, f.UncompressedSize64, limit)
		}
		data, err := readEntry(f, limit)
		if err != nil {
			return b, err
		}
		total += int64(len(data))
		if total > MaxBundleBytes {
			return b, fail(ErrLimit, "the contents exceed %d bytes", MaxBundleBytes)
		}
		files[name] = data
	}
	raw, ok := files[ManifestFile]
	if !ok {
		return b, fail(ErrFormat, "no %s", ManifestFile)
	}
	sig, ok := files[SignatureFile]
	if !ok {
		return b, fail(ErrFormat, "no %s", SignatureFile)
	}
	m, err := DecodeManifest(raw)
	if err != nil {
		return b, err
	}
	b.Manifest, b.ManifestBytes, b.Signature = m, raw, strings.TrimSpace(string(sig))
	listed := map[string]bool{ManifestFile: true, SignatureFile: true}
	for _, mi := range m.Items {
		listed[mi.Path] = true
		data, ok := files[mi.Path]
		if !ok {
			return b, fail(ErrPath, "item %q: %q is not in the bundle", mi.Name, mi.Path)
		}
		h := sha256.Sum256(data)
		if int64(len(data)) != mi.Size || hex.EncodeToString(h[:]) != mi.SHA256 {
			return b, fail(ErrDigest, "item %q", mi.Name)
		}
		if !textOnly(data) {
			return b, fail(ErrExecutable, "item %q is not text", mi.Name)
		}
		it := Item{ManifestItem: mi, Data: data}
		if err := decodeItem(&it, m.Publisher); err != nil {
			return b, err
		}
		b.Items = append(b.Items, it)
	}
	for name := range files {
		if !listed[name] {
			return b, fail(ErrPath, "%q is not listed in bundle.json", name)
		}
	}
	return b, nil
}

// checkEntry allows regular files at bundle.json, bundle.jws and
// items/<kind>/<file>, and the directory entries items/ and items/<kind>/;
// nothing else: no symlink, device, absolute or parent path, encryption or
// unusual compression.
func checkEntry(f *zip.File) error {
	name := f.Name
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || strings.Contains(name, "//") {
		return fail(ErrPath, "%q", name)
	}
	if f.Flags&0x1 != 0 {
		return fail(ErrFormat, "%q is encrypted", name)
	}
	if f.Method != zip.Store && f.Method != zip.Deflate {
		return fail(ErrFormat, "%q: compression method %d", name, f.Method)
	}
	mode := f.Mode()
	if strings.HasSuffix(name, "/") {
		dir := strings.TrimSuffix(name, "/")
		parts := strings.Split(dir, "/")
		ok := (len(parts) == 1 && parts[0] == ItemsDir) || (len(parts) == 2 && parts[0] == ItemsDir && Kind(parts[1]).Valid())
		if !ok || mode&fs.ModeType&^fs.ModeDir != 0 {
			return fail(ErrPath, "directory %q", name)
		}
		return nil
	}
	if mode&fs.ModeType != 0 {
		return fail(ErrPath, "%q is not a regular file", name)
	}
	if mode&0o111 != 0 {
		return fail(ErrExecutable, "%q has an executable mode", name)
	}
	if path.Clean(name) != name {
		return fail(ErrPath, "%q", name)
	}
	if name == ManifestFile || name == SignatureFile {
		return nil
	}
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[0] != ItemsDir || !Kind(parts[1]).Valid() {
		return fail(ErrPath, "%q", name)
	}
	return checkItemPath(Kind(parts[1]), name)
}

// readEntry reads at most limit bytes of f; a larger entry is refused.
func readEntry(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fail(ErrFormat, "%q: %v", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fail(ErrFormat, "%q: %v", f.Name, err)
	}
	if int64(len(data)) > limit {
		return nil, fail(ErrLimit, "%q exceeds %d bytes", f.Name, limit)
	}
	return data, nil
}
