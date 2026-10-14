// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"errors"
	"time"
)

// Freshness contract bounds (F440, HR-211, G0 M9 decision 3).
const (
	DefaultEnforcedTTL   = 24 * time.Hour
	MinEnforcedTTL       = time.Hour
	MaxEnforcedTTL       = 7 * 24 * time.Hour
	DefaultReassessEvery = time.Minute
	MinReassessEvery     = 10 * time.Second
	MaxReassessEvery     = time.Hour
)

// Freshness is the published freshness contract: how long closure evidence
// supports ENFORCED, how often pending changes are reassessed at most, and
// what an expired or invalidated ENFORCED record reads as.
type Freshness struct {
	EnforcedTTL   time.Duration
	ReassessEvery time.Duration
}

// StaleState is the highest state an ENFORCED record reads as after it
// expired or a change invalidated it: the scope is recomputed from current
// evidence and capped here, so it may read lower. Work continues
// (decision 3).
const StaleState = Partial

// NewFreshness applies the defaults to zero values and checks the bounds.
func NewFreshness(ttl, reassess time.Duration) (Freshness, error) {
	if ttl == 0 {
		ttl = DefaultEnforcedTTL
	}
	if reassess == 0 {
		reassess = DefaultReassessEvery
	}
	if ttl < MinEnforcedTTL || ttl > MaxEnforcedTTL {
		return Freshness{}, errors.New("coverage.enforced_ttl must be between 1h and 168h")
	}
	if reassess < MinReassessEvery || reassess > MaxReassessEvery {
		return Freshness{}, errors.New("coverage.reassess_every must be between 10s and 1h")
	}
	return Freshness{EnforcedTTL: ttl, ReassessEvery: reassess}, nil
}
