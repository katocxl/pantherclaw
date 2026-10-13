// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/anchoring"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// EvidenceConfig configures the evidence log (G0 M7 track B, design
// decisions 8 and 16).
type EvidenceConfig struct {
	// LogOrigin names the deployment's evidence log: each org's checkpoints
	// have the origin "<log origin>/org/<org id>" (PAP-1 §9.4), and trust
	// files pin it. Empty: auth.public_url without its scheme, for example
	// "pantherclaw.example.com". Keep it stable: a new origin starts new
	// checkpoint histories for verifiers.
	LogOrigin string `json:"log_origin" env:"PC_EVIDENCE_LOG_ORIGIN"`
	// CheckpointInterval is how often each org whose chain grew gets a new
	// signed checkpoint: 1 to 60 minutes, 5 minutes when unset (design
	// decision 8).
	CheckpointInterval config.Duration `json:"checkpoint_interval" env:"PC_EVIDENCE_CHECKPOINT_INTERVAL"`
	// MLDSACosign adds an ML-DSA-65 co-signature from the checkpoints_pq key
	// to every checkpoint (decision 6, Enterprise). Off by default.
	MLDSACosign bool `json:"mldsa_cosign" env:"PC_EVIDENCE_MLDSA_COSIGN"`
	// Anchoring enters a blinded global root of every org's latest
	// checkpoint in a transparency log, with a timestamp (design decision
	// 12, HR-195; Team edition). Off by default.
	Anchoring AnchoringConfig `json:"anchoring"`
}

// AnchoringConfig configures the anchored global root (G0 M7 design
// decision 12). Nothing is hard-coded: Sigstore retires its Rekor v2 logs
// and rotates keys, so the operator names the log, its key and origin, and
// the timestamp authority with its certificate chain
// (docs/runbooks/anchoring.md).
type AnchoringConfig struct {
	// Comment is ignored: it lets a configuration file say where its values
	// come from and how to update them.
	Comment string `json:"_comment"`
	// Enabled turns anchoring on (Team edition: refused at start on a
	// Community licence).
	Enabled bool `json:"enabled" env:"PC_EVIDENCE_ANCHORING_ENABLED"`
	// Interval is the anchoring period: 5 minutes to 24 hours, an hour when
	// unset.
	Interval config.Duration `json:"interval" env:"PC_EVIDENCE_ANCHORING_INTERVAL"`
	// Rekor is the Rekor v2 transparency log.
	Rekor RekorConfig `json:"rekor"`
	// TSA is the RFC 3161 timestamp authority.
	TSA TSAConfig `json:"tsa"`
}

// RekorConfig names a Rekor v2 log.
type RekorConfig struct {
	// URL is the log's https base URL, for example
	// https://log2025-1.rekor.sigstore.dev.
	URL string `json:"url" env:"PC_EVIDENCE_REKOR_URL"`
	// PublicKeyFile holds the log's checkpoint key: PEM "PUBLIC KEY" (PKIX,
	// Ed25519 or ECDSA P-256), as Sigstore's trusted_root.json lists it.
	PublicKeyFile string `json:"public_key_file" env:"PC_EVIDENCE_REKOR_PUBLIC_KEY_FILE"`
	// Origin is the log's checkpoint origin; empty: the URL without its
	// scheme (Rekor v2's convention).
	Origin string `json:"origin" env:"PC_EVIDENCE_REKOR_ORIGIN"`
}

// TSAConfig names an RFC 3161 timestamp authority.
type TSAConfig struct {
	// URL is the authority's https endpoint, for example
	// https://timestamp.sigstore.dev/api/v1/timestamp.
	URL string `json:"url" env:"PC_EVIDENCE_TSA_URL"`
	// CertChainFile holds its certificate chain in PEM: the signing
	// certificate first, the root last.
	CertChainFile string `json:"cert_chain_file" env:"PC_EVIDENCE_TSA_CERT_CHAIN_FILE"`
}

// maxLogOrigin leaves room for "/org/<org id>/ml-dsa-65" within a signed
// note's 256-byte key names.
const maxLogOrigin = 200

// logOrigin returns the configured log origin, or the one derived from
// auth.public_url.
func (c *Config) logOrigin() string {
	if c.Evidence.LogOrigin != "" {
		return c.Evidence.LogOrigin
	}
	u, err := url.Parse(c.Auth.PublicURL)
	if err != nil {
		return ""
	}
	return u.Host + strings.TrimSuffix(u.EscapedPath(), "/")
}

// validLogOrigin: printable, no spaces or plus signs (signed-note key
// names), no scheme, at most maxLogOrigin bytes.
func validLogOrigin(o string) bool {
	return o != "" && len(o) <= maxLogOrigin && !strings.Contains(o, "://") && !strings.ContainsRune(o, '+') &&
		strings.IndexFunc(o, func(r rune) bool { return unicode.IsSpace(r) || r < 0x21 || r == 0x7f }) < 0
}

func (c *Config) validateEvidence() []error {
	var errs []error
	if !validLogOrigin(c.logOrigin()) {
		errs = append(errs, errors.New("evidence.log_origin must be 1..200 printable bytes without a scheme, spaces or '+' "+
			"(for example pantherclaw.example.com)"))
	}
	if d := c.Evidence.CheckpointInterval.D(); d != 0 && (d < time.Minute || d > time.Hour) {
		errs = append(errs, errors.New("evidence.checkpoint_interval must be 1m..60m"))
	}
	return append(errs, c.Evidence.Anchoring.validate()...)
}

// Anchoring interval bounds.
const (
	minAnchoringInterval = 5 * time.Minute
	maxAnchoringInterval = 24 * time.Hour
)

// httpsBase reports whether s is an https URL with a host and no user,
// query or fragment.
func httpsBase(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" &&
		!u.ForceQuery
}

func (a AnchoringConfig) validate() []error {
	var errs []error
	if d := a.Interval.D(); d != 0 && (d < minAnchoringInterval || d > maxAnchoringInterval) {
		errs = append(errs, errors.New("evidence.anchoring.interval must be 5m..24h"))
	}
	if !a.Enabled {
		return errs
	}
	if !httpsBase(a.Rekor.URL) {
		errs = append(errs, errors.New("evidence.anchoring.rekor.url must be an https URL (for example https://log2025-1.rekor.sigstore.dev)"))
	}
	if a.Rekor.PublicKeyFile == "" {
		errs = append(errs, errors.New("evidence.anchoring.rekor.public_key_file is required: the log's key from Sigstore's trusted_root.json"))
	}
	if o := a.rekorOrigin(); !validLogOrigin(o) {
		errs = append(errs, errors.New("evidence.anchoring.rekor.origin must be the log's checkpoint origin, without a scheme"))
	}
	if !httpsBase(a.TSA.URL) {
		errs = append(errs, errors.New("evidence.anchoring.tsa.url must be an https URL (for example https://timestamp.sigstore.dev/api/v1/timestamp)"))
	}
	if a.TSA.CertChainFile == "" {
		errs = append(errs, errors.New("evidence.anchoring.tsa.cert_chain_file is required: the authority's PEM chain, signing certificate first"))
	}
	return errs
}

// rekorOrigin returns the configured log origin, or the URL without its
// scheme.
func (a AnchoringConfig) rekorOrigin() string {
	if a.Rekor.Origin != "" {
		return a.Rekor.Origin
	}
	u, err := url.Parse(a.Rekor.URL)
	if err != nil {
		return ""
	}
	return u.Host + strings.TrimSuffix(u.EscapedPath(), "/")
}

// anchoringInterval returns evidence.anchoring.interval or its default.
func (c *Config) anchoringInterval() time.Duration {
	if d := c.Evidence.Anchoring.Interval.D(); d != 0 {
		return d
	}
	return anchoring.DefaultInterval
}

// checkpointInterval returns evidence.checkpoint_interval or its default.
func (c *Config) checkpointInterval() time.Duration {
	if d := c.Evidence.CheckpointInterval.D(); d != 0 {
		return d
	}
	return checkpoints.DefaultInterval
}

// evidenceKeyPurposes are the signing keys the configuration needs beyond
// those every deployment has: the checkpoints_pq key for co-signing.
func (c *Config) evidenceKeyPurposes() []keys.Purpose {
	if c.Evidence.MLDSACosign {
		return []keys.Purpose{keys.PurposeCheckpointsPQ}
	}
	return nil
}

// errMLDSAEdition refuses ML-DSA co-signing without an Enterprise licence.
var errMLDSAEdition = errors.New("evidence.mldsa_cosign needs an Enterprise licence; turn it off or install one")

// errAnchoringEdition refuses anchoring on a Community licence (PN-007.3).
var errAnchoringEdition = errors.New("evidence.anchoring needs a Team licence or higher; " +
	"set evidence.anchoring.enabled to false or install a licence")

// checkEvidenceEdition refuses settings the licence does not include.
func (c *Config) checkEvidenceEdition(e domain.Entitlements) error {
	if c.Evidence.MLDSACosign && !e.MLDSACosign() {
		return errMLDSAEdition
	}
	if c.Evidence.Anchoring.Enabled && !e.Edition.Paid() {
		return errAnchoringEdition
	}
	return nil
}
