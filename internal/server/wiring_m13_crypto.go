// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/fips140"
	"log/slog"
)

// FIPS mode (G0 M13 D35, PN-019.1, HR-396). A FIPS build (GOFIPS140, the
// *-fips release binaries) runs on the validated Go Cryptographic Module,
// which does not include ML-DSA yet: ML-DSA-65 co-signing of checkpoints and
// evidence packs is turned off, logged once at start, until a validated
// module includes it. Sealing (MLKEM768-P256) and the IdP RSA floor live in
// their packages; TLS is the same in both builds.

// fipsMode reports FIPS 140-3 mode; tests replace it.
var fipsMode = fips140.Enabled

// applyFIPSMode adjusts the configuration for FIPS mode before the
// licence check and key loading.
func applyFIPSMode(ctx context.Context, cfg *Config, log *slog.Logger) {
	if !fipsMode() {
		return
	}
	if cfg.Evidence.MLDSACosign {
		cfg.Evidence.MLDSACosign = false
		log.WarnContext(ctx, "fips.mldsa_cosign_off",
			slog.String("reason", "ML-DSA is not in the validated FIPS 140-3 module; checkpoints and evidence packs are signed with Ed25519 only"))
	}
}
