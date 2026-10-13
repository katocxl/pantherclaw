// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// Bounds of coverage.claim_timeout.
const (
	minClaimTimeout = 10 * time.Millisecond
	maxClaimTimeout = 2 * time.Second
)

// CoverageConfig is coverage's freshness contract (G0 M9 track A, decision
// 3; F440, HR-211).
type CoverageConfig struct {
	// EnforcedTTL is how long sandbox closure evidence supports ENFORCED:
	// 1 to 168 hours, 24 hours when unset.
	EnforcedTTL config.Duration `json:"enforced_ttl" env:"PC_COVERAGE_ENFORCED_TTL"`
	// ReassessEvery is how often the worker reassesses the scopes that
	// changed: 10 seconds to 1 hour, a minute when unset.
	ReassessEvery config.Duration `json:"reassess_every" env:"PC_COVERAGE_REASSESS_EVERY"`
	// ClaimTimeout bounds the coverage claim read on the decision path; a
	// receipt whose claim takes longer says it is unavailable (HR-217):
	// 10 milliseconds to 2 seconds, 50 milliseconds when unset.
	ClaimTimeout config.Duration `json:"claim_timeout" env:"PC_COVERAGE_CLAIM_TIMEOUT"`
}

// freshness returns the published freshness contract.
func (c *Config) freshness() (coverage.Freshness, error) {
	return coverage.NewFreshness(c.Coverage.EnforcedTTL.D(), c.Coverage.ReassessEvery.D())
}

// claimTimeout returns the coverage claim timeout.
func (c *Config) claimTimeout() (time.Duration, error) {
	d := c.Coverage.ClaimTimeout.D()
	if d == 0 {
		return finalize.DefaultClaimTimeout, nil
	}
	if d < minClaimTimeout || d > maxClaimTimeout {
		return 0, errors.New("coverage.claim_timeout must be between 10ms and 2s")
	}
	return d, nil
}

func (c *Config) validateCoverage() []error {
	var errs []error
	if _, err := c.freshness(); err != nil {
		errs = append(errs, err)
	}
	if _, err := c.claimTimeout(); err != nil {
		errs = append(errs, err)
	}
	return errs
}
