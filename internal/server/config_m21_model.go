// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"
)

// ModelConfig is the server's part of model drafting (G0 M21 D309; G16).
type ModelConfig struct {
	// Enabled allows model drafting at all. It defaults to false, is both the
	// self-hosted gate and the platform kill switch, and changes with a
	// restart; an organization's own switch is the runtime one.
	Enabled bool `json:"enabled" env:"PC_MODEL_DRAFTING_ENABLED"`
	// CallsPerMinute (default 10) bounds one organization's calls. It is the
	// default and the maximum: an organization can only lower it.
	CallsPerMinute int `json:"calls_per_minute" env:"PC_MODEL_CALLS_PER_MINUTE"`
	// TokensPerDay (default 200000) bounds one organization's tokens a UTC
	// day. It is the default and the maximum too.
	TokensPerDay int64 `json:"tokens_per_day" env:"PC_MODEL_TOKENS_PER_DAY"`
}

// Defaults of the model caps (D309).
const (
	defaultModelCallsPerMinute = 10
	defaultModelTokensPerDay   = 200_000
	maxModelCallsPerMinute     = 10_000
	maxModelTokensPerDay       = 1_000_000_000_000
)

func defaultModel() ModelConfig {
	return ModelConfig{CallsPerMinute: defaultModelCallsPerMinute, TokensPerDay: defaultModelTokensPerDay}
}

func (c *Config) validateModel() []error {
	var errs []error
	if n := c.Model.CallsPerMinute; n < 1 || n > maxModelCallsPerMinute {
		errs = append(errs, fmt.Errorf("model.calls_per_minute must be 1 to %d", maxModelCallsPerMinute))
	}
	if n := c.Model.TokensPerDay; n < 1 || n > maxModelTokensPerDay {
		errs = append(errs, fmt.Errorf("model.tokens_per_day must be 1 to %d", int64(maxModelTokensPerDay)))
	}
	return errs
}
