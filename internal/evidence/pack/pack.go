// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pack defines the pantherclaw.pack/v1 evidence pack (G0 M7 design
// decision 15, HR-196, F525–F532): a ZIP of canonical JSON files and a
// signed manifest. The manifest (manifest.jws, a compact JWS of type
// pap-pack+jwt signed by the deployment's evidence_packs key) lists every
// file with its SHA-256 and size, the effect state of every transaction in
// the scope (unknown, conflicting and pending included), the versions that
// applied, containment and restoration events, the exporter, the time, the
// retention limits and redactions, every gap with its reason, the latest
// checkpoint and anchor, and the fixed sentence "This pack supports review;
// it does not certify compliance." When ML-DSA co-signing is on, the
// manifest's signing input is also signed with the checkpoints_pq key
// (manifest.mldsa65.json).
//
// The package performs no I/O: the server builds packs with it and `pclaw
// verify` reads them offline (internal/evidence/bundle.VerifyPack).
package pack

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Format identifiers and fixed texts.
const (
	Format  = "pantherclaw.pack/v1"
	JWSType = "pap-pack+jwt"
	// Statement is the fixed sentence every manifest carries (F526).
	Statement = "This pack supports review; it does not certify compliance."
	// ManifestPath and CosignPath are the files outside the item list.
	ManifestPath = "manifest.jws"
	CosignPath   = "manifest.mldsa65.json"
	// CosignContext separates the ML-DSA-65 co-signature of a manifest
	// from every other use of the checkpoints_pq key.
	CosignContext = "pantherclaw.pack/v1"
)

// Limits.
const (
	// MaxContentBytes caps a pack's ZIP (design decision 15).
	MaxContentBytes = 64 << 20
	// MaxFiles caps the files of a pack.
	MaxFiles = 20_000
	// MaxFileBytes caps one file, uncompressed.
	MaxFileBytes = 32 << 20
	// maxTotalBytes caps all files, uncompressed (a ZIP bomb stops here).
	maxTotalBytes = 256 << 20
	// MaxManifestBytes caps the manifest JWS.
	MaxManifestBytes = 16 << 20
	maxPathBytes     = 200
)

// Gap reasons (F532).
const (
	GapRemoved           = "removed"
	GapOutsidePermission = "outside_permission"
	GapNotCaptured       = "not_captured"
	GapNotCheckpointed   = "not_checkpointed"
	GapNotAnchored       = "not_anchored"
	GapLimit             = "limit"
	GapNotFound          = "not_found"
)

// Item kinds.
const (
	KindTransaction = "transaction"
	KindVersions    = "versions"
	KindApprovals   = "approvals"
	KindContainment = "containment"
	// KindBundle is a pantherclaw.bundle/v1 verify bundle: the receipts'
	// ledger entries with their inclusion proofs, the checkpoints and the
	// anchor.
	KindBundle = "bundle"
)

// Scope kinds (design decision 15).
const (
	ScopeTransactions = "transactions"
	ScopeRun          = "run"
	ScopeAgent        = "agent"
	ScopeTimeRange    = "time_range"
)

// ErrInvalid reports a pack or manifest that is malformed or does not
// verify.
var ErrInvalid = errors.New("pack: invalid pantherclaw.pack/v1")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Manifest is the signed list of a pack.
type Manifest struct {
	Format       string             `json:"format"`
	Pack         string             `json:"pack"`
	Org          string             `json:"org"`
	Origin       string             `json:"origin"` // <log origin>/org/<org>
	Exporter     Exporter           `json:"exporter"`
	Created      string             `json:"created_at"` // RFC 3339
	Expires      string             `json:"expires_at"`
	Scope        Scope              `json:"scope"`
	Include      Include            `json:"include"`
	Filters      []string           `json:"filters"`
	Items        []Item             `json:"items"`
	Transactions []TransactionState `json:"transactions"`
	EffectStates map[string]int     `json:"effect_states"`
	Versions     *Versions          `json:"versions,omitzero"`
	Containment  []Event            `json:"containment,omitzero"`
	Retention    []Retention        `json:"retention"`
	Redactions   []string           `json:"redactions"`
	Gaps         []Gap              `json:"gaps"`
	Checkpoint   *Checkpoint        `json:"checkpoint,omitzero"`
	Anchor       *Anchor            `json:"anchor,omitzero"`
	Statement    string             `json:"statement"`
}

// Exporter is who created the pack.
type Exporter struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Scope is what the pack covers.
type Scope struct {
	Kind         string   `json:"kind"`
	Transactions []string `json:"transactions,omitzero"`
	Run          string   `json:"run,omitzero"`
	Agent        string   `json:"agent,omitzero"`
	From         string   `json:"from,omitzero"`
	To           string   `json:"to,omitzero"`
}

// Include is what the creator asked for.
type Include struct {
	Receipts    bool `json:"receipts"`
	Versions    bool `json:"versions"`
	Approvals   bool `json:"approvals"`
	Containment bool `json:"containment"`
	Captures    bool `json:"captures"`
}

// Item is one file of the pack.
type Item struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"` // hex
	Size   int64  `json:"size"`
}

// TransactionState is one transaction's states, side by side (F479, F528).
type TransactionState struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Decision  string `json:"decision"`
	Execution string `json:"execution_state"`
	// Outcome is what the dispatch reported: accepted, failed or unknown.
	Outcome string `json:"outcome,omitzero"`
	// Effect is the recorded effect state; an unknown outcome without one
	// is UNKNOWN (never success). It is empty when nothing was dispatched,
	// or no verification ran yet.
	Effect   string `json:"effect_state,omitzero"`
	Required string `json:"effect_level_required,omitzero"`
	Achieved string `json:"effect_level_achieved,omitzero"`
	Monitor  bool   `json:"monitor,omitzero"`
}

// Versions are the revisions the decisions of the scope applied (F527).
type Versions struct {
	Policies    []string `json:"policies,omitzero"`
	Definitions []string `json:"definitions,omitzero"`
	Levels      []Level  `json:"levels,omitzero"`
	Connections []string `json:"connections,omitzero"`
	Approvals   []string `json:"approvals,omitzero"`
}

// Level is a grant or guardrail revision.
type Level struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}

// Event is a containment or restoration event (F529).
type Event struct {
	Entry string `json:"entry"`
	Kind  string `json:"kind"`
	At    string `json:"at"`
	// Object is what it concerned: an agent, a connection, or the org.
	Object string `json:"object,omitzero"`
}

// Retention is the retention of one category of evidence (F530).
type Retention struct {
	Category string `json:"category"`
	Days     int    `json:"days"`
	Source   string `json:"source"`
}

// Gap is something the pack does not hold, and why (F532).
type Gap struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
	Detail  string `json:"detail"`
}

// Checkpoint is the org's latest checkpoint when the pack was built.
type Checkpoint struct {
	Size uint64 `json:"size"`
	Note string `json:"note"`
}

// Anchor is the newest anchor of one of the org's checkpoints.
type Anchor struct {
	Period     string `json:"period"`
	Checkpoint uint64 `json:"checkpoint"`
	Root       string `json:"root"` // base64
}

// Canonical returns v as RFC 8785 canonical JSON.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	c := jsontext.Value(raw)
	if err := c.Canonicalize(); err != nil {
		return nil, err
	}
	return c, nil
}

// File is one file of a pack.
type File struct {
	Path string
	Kind string
	Data []byte
}

var pathPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*(/[a-z0-9][a-z0-9_.-]*)*$`)

// ValidPath reports whether p is a safe pack path: lower-case segments of
// letters, digits, '.', '_' and '-', no "..", at most 200 bytes.
func ValidPath(p string) bool {
	return len(p) <= maxPathBytes && pathPattern.MatchString(p) && !strings.Contains(p, "..")
}

// ItemOf returns the manifest item of a file.
func ItemOf(f File) Item {
	sum := sha256.Sum256(f.Data)
	return Item{Path: f.Path, Kind: f.Kind, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.Data))}
}

// Write returns the pack's ZIP: the files in path order, then the manifest
// and its co-signature when there is one, all stamped with modified, so the
// same pack gives the same bytes.
func Write(files []File, manifestJWS string, cosign []byte, modified time.Time) ([]byte, error) {
	all := make([]File, 0, len(files)+2)
	all = append(all, files...)
	slices.SortFunc(all, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	all = append(all, File{Path: ManifestPath, Data: []byte(manifestJWS)})
	if len(cosign) > 0 {
		all = append(all, File{Path: CosignPath, Data: cosign})
	}
	if len(all) > MaxFiles+2 {
		return nil, invalid("more than %d files", MaxFiles)
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	seen := map[string]bool{}
	for _, f := range all {
		if !ValidPath(f.Path) || seen[f.Path] || len(f.Data) > MaxFileBytes {
			return nil, invalid("file %q: an invalid or repeated path, or larger than %d bytes", truncate(f.Path), MaxFileBytes)
		}
		seen[f.Path] = true
		fw, err := w.CreateHeader(&zip.FileHeader{Name: f.Path, Method: zip.Deflate, Modified: modified.UTC()})
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxContentBytes {
		return nil, fmt.Errorf("%w: the pack is larger than %d bytes", ErrTooLarge, MaxContentBytes)
	}
	return buf.Bytes(), nil
}

// ErrTooLarge reports a pack above MaxContentBytes.
var ErrTooLarge = errors.New("pack: too large")

// Read opens a pack's ZIP and returns its files by path, refusing unsafe
// or repeated names, directories, and files or totals above the limits.
func Read(b []byte) (map[string][]byte, error) {
	if len(b) > MaxContentBytes {
		return nil, invalid("larger than %d bytes", MaxContentBytes)
	}
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, invalid("not a ZIP: %v", err)
	}
	if len(r.File) > MaxFiles+2 {
		return nil, invalid("more than %d files", MaxFiles)
	}
	out := make(map[string][]byte, len(r.File))
	total := int64(0)
	for _, f := range r.File {
		if !ValidPath(f.Name) || f.FileInfo().IsDir() {
			return nil, invalid("unsafe file name %q", truncate(f.Name))
		}
		if _, dup := out[f.Name]; dup {
			return nil, invalid("file %q appears twice", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, invalid("file %q: %v", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, MaxFileBytes+1))
		_ = rc.Close()
		if err != nil {
			return nil, invalid("file %q: %v", f.Name, err)
		}
		if len(data) > MaxFileBytes {
			return nil, invalid("file %q is larger than %d bytes", f.Name, MaxFileBytes)
		}
		if total += int64(len(data)); total > maxTotalBytes {
			return nil, invalid("the files are larger than %d bytes in all", maxTotalBytes)
		}
		out[f.Name] = data
	}
	return out, nil
}

// header is the only protected header a manifest may have.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Signed is a parsed manifest JWS, not verified yet.
type Signed struct {
	Kid          string
	Payload      []byte
	Signature    []byte
	SigningInput []byte // base64url(header) "." base64url(payload)
}

// ParseJWS splits a compact manifest JWS and checks its header: EdDSA,
// type pap-pack+jwt, a kid, nothing else.
func ParseJWS(compact string) (Signed, error) {
	if len(compact) > MaxManifestBytes {
		return Signed{}, invalid("the manifest is larger than %d bytes", MaxManifestBytes)
	}
	parts := strings.Split(strings.TrimSpace(compact), ".")
	if len(parts) != 3 {
		return Signed{}, invalid("the manifest is not a compact JWS")
	}
	enc := base64.RawURLEncoding.Strict()
	rawHeader, err := enc.DecodeString(parts[0])
	if err != nil {
		return Signed{}, invalid("manifest header: %v", err)
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h, json.RejectUnknownMembers(true)); err != nil {
		return Signed{}, invalid("manifest header: %v", err)
	}
	if h.Alg != "EdDSA" || h.Typ != JWSType || h.Kid == "" || len(h.Kid) > 128 {
		return Signed{}, invalid("the manifest header must be EdDSA, typ %s, with a kid", JWSType)
	}
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return Signed{}, invalid("manifest payload: %v", err)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Signed{}, invalid("manifest signature is malformed")
	}
	return Signed{Kid: h.Kid, Payload: payload, Signature: sig, SigningInput: []byte(parts[0] + "." + parts[1])}, nil
}

// Verify checks the manifest's Ed25519 signature with pub.
func (s Signed) Verify(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, s.SigningInput, s.Signature)
}

// DecodeManifest decodes a manifest strictly and checks its shape.
func DecodeManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalid("manifest: %v", err)
	}
	switch {
	case m.Format != Format:
		return nil, invalid("manifest format %q", truncate(m.Format))
	case m.Pack == "" || m.Org == "" || m.Origin == "":
		return nil, invalid("the manifest names no pack, org or origin")
	case len(m.Items) > MaxFiles:
		return nil, invalid("more than %d items", MaxFiles)
	}
	if _, err := time.Parse(time.RFC3339, m.Created); err != nil {
		return nil, invalid("manifest created_at: %v", err)
	}
	for _, it := range m.Items {
		if !ValidPath(it.Path) || it.Path == ManifestPath || it.Path == CosignPath || len(it.SHA256) != 64 || it.Size < 0 {
			return nil, invalid("malformed item %q", truncate(it.Path))
		}
	}
	return &m, nil
}

// Cosign is the ML-DSA-65 co-signature of a manifest's signing input.
type Cosign struct {
	Algorithm string `json:"alg"` // "ML-DSA-65"
	Kid       string `json:"kid"`
	Signature []byte `json:"sig"`
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}
