// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/identity/adapters/awssts"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// presetAttestors adds the M17 presets (PN-002.3) to att: each one's
// issuers come from operator configuration or a pinned vendor URL only
// (HR-142).
func presetAttestors(att *iapp.Attestors, cfg IdentityConfig) error {
	gitlab, err := issuerkeys.NewGitLabDirectory(cfg.GitLabIssuers, attestTimeout)
	if err != nil {
		return err
	}
	spiffe, err := issuerkeys.NewSPIFFEDirectory(cfg.SPIFFETrustDomains, attestTimeout)
	if err != nil {
		return err
	}
	gcp, err := issuerkeys.NewFetcher(httpx.NewEgressClient(httpx.EgressConfig{Timeout: attestTimeout}), issuerkeys.Config{
		JWKSURL: issuers.GCPKeysURL, Algorithms: issuers.GCPAlgorithms,
	}, nil)
	if err != nil {
		return err
	}
	aws, err := awssts.New(httpx.NewEgressClient(httpx.EgressConfig{Timeout: attestTimeout}), cfg.AWSSTSHosts, nil)
	if err != nil {
		return err
	}
	att.GitLab, att.SPIFFE, att.GCP, att.AWS = gitlab, spiffe, gcp, aws
	return nil
}
