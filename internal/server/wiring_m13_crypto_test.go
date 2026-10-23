// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
)

// TestHR396_MLDSACoSigningIsOffInFIPSMode: a FIPS build signs checkpoints
// and packs without ML-DSA (not in the validated module), loads no
// checkpoints_pq key, says so in one log line, and does not refuse the
// configuration for it; outside FIPS mode nothing changes.
func TestHR396_MLDSACoSigningIsOffInFIPSMode(t *testing.T) {
	prev := fipsMode
	t.Cleanup(func() { fipsMode = prev })
	for _, fips := range []bool{false, true} {
		fipsMode = func() bool { return fips }
		var logs bytes.Buffer
		cfg := DefaultConfig()
		cfg.Evidence.MLDSACosign = true
		applyFIPSMode(context.Background(), &cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
		lines := strings.Count(logs.String(), `"msg":"fips.mldsa_cosign_off"`)
		switch {
		case fips && (cfg.Evidence.MLDSACosign || len(cfg.evidenceKeyPurposes()) != 0 || lines != 1):
			t.Errorf("FIPS mode: cosign %v, purposes %v, %d log lines", cfg.Evidence.MLDSACosign, cfg.evidenceKeyPurposes(), lines)
		case fips:
			// A Team licence would refuse ML-DSA co-signing; off, it passes.
			if err := cfg.checkEvidenceEdition(domain.Entitlements{Edition: domain.Team}); err != nil {
				t.Errorf("FIPS mode, Team licence: %v", err)
			}
		case !fips && (!cfg.Evidence.MLDSACosign || lines != 0):
			t.Errorf("outside FIPS mode: cosign %v, %d log lines", cfg.Evidence.MLDSACosign, lines)
		}
	}
}
