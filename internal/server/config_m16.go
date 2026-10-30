// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"
	"net/url"
	"strings"
)

// ExternalChecksConfig configures external policy checks (G0 M16 D81,
// HR-438).
type ExternalChecksConfig struct {
	// AllowedPrefixes are the endpoint prefixes an org's check may use, for
	// example https://opa.example.com/v1/data/. Operator configuration only:
	// without one, no check can be created or activated.
	AllowedPrefixes []string `json:"allowed_prefixes" env:"PC_EXTERNAL_CHECKS_ALLOWED_PREFIXES"`
}

func (c *Config) validateExternalChecks() []error {
	var errs []error
	if c.Dev.ExternalChecksLoopback {
		if err := c.localOnly(); err != nil {
			errs = append(errs, fmt.Errorf("dev.external_checks_loopback is development-only: %w", err))
		}
	}
	for _, p := range c.ExternalChecks.AllowedPrefixes {
		u, err := url.Parse(p)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
			strings.ContainsAny(p, " \t\r\n\\") {
			errs = append(errs, fmt.Errorf("external_checks.allowed_prefixes: %q must be an https URL with a host and no credentials, query or fragment", p))
		}
	}
	return errs
}
