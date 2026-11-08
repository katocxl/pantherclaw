// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
)

// l3Attestors adds the L3 presets to att (G0 M35 D1030): spiffe_x509
// verifies against the X.509 authorities of the operator-configured trust
// domains (identity.spiffe_trust_domains, HR-142), and gcp_instance uses the
// pinned Google keys the gcp_workload preset already holds (att.GCP).
func l3Attestors(att *iapp.Attestors, cfg IdentityConfig) error {
	x509, err := issuerkeys.NewSPIFFEX509Directory(cfg.SPIFFETrustDomains, attestTimeout)
	if err != nil {
		return err
	}
	att.SPIFFEX509 = x509
	return nil
}
