// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
)

// presetAttestors adds the M17 presets (PN-002.3) to att: each one's
// issuers come from operator configuration only (HR-142).
func presetAttestors(att *iapp.Attestors, cfg IdentityConfig) error {
	gitlab, err := issuerkeys.NewGitLabDirectory(cfg.GitLabIssuers, attestTimeout)
	if err != nil {
		return err
	}
	att.GitLab = gitlab
	return nil
}
