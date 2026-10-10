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
	return errs
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

// checkEvidenceEdition refuses settings the licence does not include.
func (c *Config) checkEvidenceEdition(e domain.Entitlements) error {
	if c.Evidence.MLDSACosign && !e.MLDSACosign() {
		return errMLDSAEdition
	}
	return nil
}
