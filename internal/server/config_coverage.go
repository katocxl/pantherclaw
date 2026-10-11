// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	coverage "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// CoverageConfig is coverage's freshness contract (G0 M9 track A, decision
// 3; F440, HR-211).
type CoverageConfig struct {
	// EnforcedTTL is how long sandbox closure evidence supports ENFORCED:
	// 1 to 168 hours, 24 hours when unset.
	EnforcedTTL config.Duration `json:"enforced_ttl" env:"PC_COVERAGE_ENFORCED_TTL"`
	// ReassessInterval is how often the worker reassesses the scopes that
	// changed: 10 seconds to 1 hour, a minute when unset.
	ReassessInterval config.Duration `json:"reassess_interval" env:"PC_COVERAGE_REASSESS_INTERVAL"`
}

// freshness returns the published freshness contract.
func (c *Config) freshness() (coverage.Freshness, error) {
	return coverage.NewFreshness(c.Coverage.EnforcedTTL.D(), c.Coverage.ReassessInterval.D())
}

func (c *Config) validateCoverage() []error {
	if _, err := c.freshness(); err != nil {
		return []error{err}
	}
	return nil
}
