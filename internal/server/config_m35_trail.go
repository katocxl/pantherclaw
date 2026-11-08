// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/evidence/note"
	"github.com/katocxl/pantherclaw/internal/evidence/witness"
)

// WitnessConfig names one witness of the deployment-wide root log (G0 M35
// D1041): the operator's name for it, its https submission prefix (the
// add-checkpoint request goes to URL + "/add-checkpoint"), and its
// cosignature/v1 verifier key, as the witness publishes it.
type WitnessConfig struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	VKey string `json:"vkey"`
}

// TUFConfig configures the Sigstore TUF client (G0 M35 D1040).
type TUFConfig struct {
	// Repository is the TUF repository's https URL; empty: Sigstore's
	// public-good repository, https://tuf-repo-cdn.sigstore.dev.
	Repository string `json:"repository" env:"PC_EVIDENCE_TUF_REPOSITORY"`
	// CacheDir keeps the verified TUF metadata between refreshes; empty:
	// nothing is cached.
	CacheDir string `json:"cache_dir" env:"PC_EVIDENCE_TUF_CACHE_DIR"`
}

// Anchoring trust sources.
const (
	anchoringTrustFile = "file"
	anchoringTrustTUF  = "tuf"
)

// maxWitnesses caps evidence.witnesses.
const maxWitnesses = 16

// tufTrust reports whether the log key and the TSA chain come from TUF.
func (a AnchoringConfig) tufTrust() bool { return a.Trust == anchoringTrustTUF }

// errWitnessesEdition refuses witnesses below the Business edition.
var errWitnessesEdition = errors.New("evidence.witnesses needs a Business licence or higher; remove the witnesses or install one")

// validateTrail checks evidence.anchoring.trust and tuf, evidence.witnesses
// and evidence.witness_threshold.
func (c *Config) validateTrail() []error {
	var errs []error
	a := c.Evidence.Anchoring
	switch a.Trust {
	case "", anchoringTrustFile, anchoringTrustTUF:
	default:
		errs = append(errs, errors.New(`evidence.anchoring.trust must be "file" or "tuf"`))
	}
	if a.TUF.Repository != "" && !httpsBase(a.TUF.Repository) {
		errs = append(errs, errors.New("evidence.anchoring.tuf.repository must be an https URL (for example https://tuf-repo-cdn.sigstore.dev)"))
	}
	ws := c.Evidence.Witnesses
	if len(ws) > 0 && !a.Enabled {
		errs = append(errs, errors.New("evidence.witnesses needs evidence.anchoring.enabled: witnesses cosign the anchored root log only"))
	}
	if len(ws) > maxWitnesses {
		errs = append(errs, fmt.Errorf("evidence.witnesses: at most %d witnesses", maxWitnesses))
	}
	seen := map[string]bool{}
	for i, w := range ws {
		if !note.ValidKeyName(w.Name) || seen[w.Name] {
			errs = append(errs, fmt.Errorf("evidence.witnesses[%d].name must be a unique name without spaces or '+'", i))
		}
		seen[w.Name] = true
		if !httpsBase(w.URL) {
			errs = append(errs, fmt.Errorf("evidence.witnesses[%d].url must be an https URL", i))
		}
		if _, err := witness.ParseVKey(w.VKey); err != nil {
			errs = append(errs, fmt.Errorf("evidence.witnesses[%d].vkey must be the witness's cosignature/v1 verifier key: %w", i, err))
		}
	}
	if t := c.Evidence.WitnessThreshold; t < 0 || t > len(ws) {
		errs = append(errs, errors.New("evidence.witness_threshold must be 0..the number of witnesses"))
	}
	return errs
}

// witnessThreshold returns evidence.witness_threshold, or every witness
// when unset.
func (c *Config) witnessThreshold() int {
	if c.Evidence.WitnessThreshold > 0 {
		return c.Evidence.WitnessThreshold
	}
	return len(c.Evidence.Witnesses)
}
