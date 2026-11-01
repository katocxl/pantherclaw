// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
)

// LimitsConfig is the API rate limits and the usage meters (G0 M13 D8,
// D10).
type LimitsConfig struct {
	API   APILimitsConfig   `json:"api"`
	Usage UsageLimitsConfig `json:"usage"`
	Scan  ScanLimitsConfig  `json:"scan"`
}

// ScanLimitsConfig bounds device scans across an org (G0 M24 D246).
type ScanLimitsConfig struct {
	// NewDeviceScopesPerKeyPerHour (default 1000) bounds the device scopes one
	// key may start an hour, counted across replicas.
	NewDeviceScopesPerKeyPerHour int `json:"new_device_scopes_per_key_per_hour" env:"PC_LIMITS_SCAN_NEW_DEVICE_SCOPES_PER_KEY_PER_HOUR"`
	// OpenDeviceScopesPerOrg (default 20000) bounds the device scopes with an
	// open discovery in one organization.
	OpenDeviceScopesPerOrg int `json:"open_device_scopes_per_org" env:"PC_LIMITS_SCAN_OPEN_DEVICE_SCOPES_PER_ORG"`
}

// APILimitsConfig bounds authenticated org calls a minute (HR-375). The
// counters are kept by each replica: with N API replicas, an org may make
// up to N times these calls a minute.
type APILimitsConfig struct {
	// PerOrgPerMinute (default 6000) bounds one organization's calls.
	PerOrgPerMinute int `json:"per_org_per_minute" env:"PC_LIMITS_API_PER_ORG_PER_MINUTE"`
	// PerCredentialPerMinute (default 1200) bounds one credential's calls:
	// an API key, a service-account key, or a person's CLI or browser
	// session.
	PerCredentialPerMinute int `json:"per_credential_per_minute" env:"PC_LIMITS_API_PER_CREDENTIAL_PER_MINUTE"`
	// ExportsPerOrgPerHour (default 30) bounds one organization's export
	// calls an hour (evidence bundles and packs, search results, cases,
	// assurance reports), counted across replicas (D45).
	ExportsPerOrgPerHour int `json:"exports_per_org_per_hour" env:"PC_LIMITS_API_EXPORTS_PER_ORG_PER_HOUR"`
}

// UsageLimitsConfig is the usage meters' enforcement (HR-377).
type UsageLimitsConfig struct {
	// Enforce would refuse use over a plan's usage limits. M13 meters
	// usage only, so true is refused.
	Enforce bool `json:"enforce" env:"PC_LIMITS_USAGE_ENFORCE"`
}

// Defaults of the API limits (D8).
const (
	defaultAPIPerOrgPerMinute        = 6000
	defaultAPIPerCredentialPerMinute = 1200
	defaultAPIExportsPerOrgPerHour   = 30
	maxAPILimit                      = 1_000_000
)

func defaultLimits() LimitsConfig {
	return LimitsConfig{API: APILimitsConfig{
		PerOrgPerMinute: defaultAPIPerOrgPerMinute, PerCredentialPerMinute: defaultAPIPerCredentialPerMinute,
		ExportsPerOrgPerHour: defaultAPIExportsPerOrgPerHour,
	}, Scan: ScanLimitsConfig{
		NewDeviceScopesPerKeyPerHour: aapp.DefaultNewDeviceScopesPerKey, OpenDeviceScopesPerOrg: aapp.DefaultOpenDeviceScopesPerOrg,
	}}
}

// validateLimits checks limits.*.
func (c *Config) validateLimits() []error {
	var errs []error
	for _, v := range []struct {
		name string
		n    int
	}{
		{"limits.api.per_org_per_minute", c.Limits.API.PerOrgPerMinute},
		{"limits.api.per_credential_per_minute", c.Limits.API.PerCredentialPerMinute},
		{"limits.api.exports_per_org_per_hour", c.Limits.API.ExportsPerOrgPerHour},
		{"limits.scan.new_device_scopes_per_key_per_hour", c.Limits.Scan.NewDeviceScopesPerKeyPerHour},
		{"limits.scan.open_device_scopes_per_org", c.Limits.Scan.OpenDeviceScopesPerOrg},
	} {
		if v.n < 1 || v.n > maxAPILimit {
			errs = append(errs, fmt.Errorf("%s must be 1 to %d", v.name, maxAPILimit))
		}
	}
	if c.Limits.Usage.Enforce {
		errs = append(errs, errors.New("limits.usage.enforce must be false: usage is metered, not enforced, in this version"))
	}
	return errs
}
