// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"strings"

	intelapp "github.com/katocxl/pantherclaw/internal/intel/app"
)

// IntelConfig is shared threat intel (G0 M38 D1103).
type IntelConfig struct {
	// FeedURL is fetched daily through the egress client and imported when
	// its signature verifies and its version rises. Empty: no fetch; the
	// operator imports with `pantherclaw-server intel import`.
	FeedURL string `json:"feed_url" env:"PC_INTEL_FEED_URL"`
}

// validateIntel checks intel.feed_url and dev.intel_key_file.
func (c *Config) validateIntel() []error {
	var errs []error
	if c.Intel.FeedURL != "" {
		if err := intelapp.CheckFeedURL(c.Intel.FeedURL); err != nil {
			errs = append(errs, err)
		}
	}
	if c.Dev.IntelKeyFile != "" {
		if !strings.HasSuffix(c.Dev.IntelKeyFile, devPublicSuffix) {
			errs = append(errs, errors.New("dev.intel_key_file must name the .pub.json file of the development intel key"))
		}
		if err := c.localOnly(); err != nil {
			errs = append(errs, fmt.Errorf("dev.intel_key_file is development-only (D1103): %w", err))
		}
	}
	return errs
}
