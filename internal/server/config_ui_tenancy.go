// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/extension"
)

// BillingConfig is how org plans are decided (G0 UI D9, D12).
type BillingConfig struct {
	// Mode: "licence" (default, self-hosted: the installed licence), "off"
	// (development: every org DEV; production refuses it, HR-359) or
	// "external" (hosted: plans come from the billing extension).
	Mode string `json:"mode" env:"PC_BILLING_MODE"`
	// RequirePlan turns on the PLAN_REQUIRED gate (HR-356); only with mode
	// external.
	RequirePlan bool `json:"require_plan" env:"PC_BILLING_REQUIRE_PLAN"`
}

// SignupConfig is self-serve sign-up (G0 UI D8, HR-351).
type SignupConfig struct {
	// SelfServe opens account sessions and CreateOrg; only with billing
	// mode external or off.
	SelfServe bool `json:"self_serve" env:"PC_SIGNUP_SELF_SERVE"`
	// MaxOrgsPerAccount (default 3) and MaxUnplannedPerAccount (default 1)
	// bound the orgs one account creates.
	MaxOrgsPerAccount      int `json:"max_orgs_per_account" env:"PC_SIGNUP_MAX_ORGS_PER_ACCOUNT"`
	MaxUnplannedPerAccount int `json:"max_unplanned_per_account" env:"PC_SIGNUP_MAX_UNPLANNED_PER_ACCOUNT"`
	// PerAccountPerHour (default 5) and PerIPPerHour (default 20) bound
	// creation attempts.
	PerAccountPerHour int `json:"per_account_per_hour" env:"PC_SIGNUP_PER_ACCOUNT_PER_HOUR"`
	PerIPPerHour      int `json:"per_ip_per_hour" env:"PC_SIGNUP_PER_IP_PER_HOUR"`
	// TermsVersion and DPAVersion, when set, are the versions a creator
	// must accept.
	TermsVersion string `json:"terms_version" env:"PC_SIGNUP_TERMS_VERSION"`
	DPAVersion   string `json:"dpa_version" env:"PC_SIGNUP_DPA_VERSION"`
}

func (c *Config) billingMode() entitlements.Mode {
	if c.Billing.Mode == "" {
		return entitlements.ModeLicence
	}
	return entitlements.Mode(c.Billing.Mode)
}

func (c *Config) signup() accounts.SignupConfig {
	s := accounts.DefaultSignup()
	s.SelfServe = c.Signup.SelfServe
	for _, v := range []struct {
		set int
		to  *int
	}{
		{c.Signup.MaxOrgsPerAccount, &s.MaxOrgsPerAccount}, {c.Signup.MaxUnplannedPerAccount, &s.MaxUnplannedPerAccount},
		{c.Signup.PerAccountPerHour, &s.PerAccountPerHour}, {c.Signup.PerIPPerHour, &s.PerIPPerHour},
	} {
		if v.set != 0 {
			*v.to = v.set
		}
	}
	s.TermsVersion, s.DPAVersion = c.Signup.TermsVersion, c.Signup.DPAVersion
	return s
}

var versionPattern = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]{0,63})?$`)

// validateTenancy checks billing and sign-up. Production refuses billing
// mode off (HR-359): every org would get every feature without a plan.
func (c *Config) validateTenancy() []error {
	var errs []error
	mode := c.billingMode()
	if !mode.Valid() {
		errs = append(errs, errors.New("billing.mode must be licence, off or external"))
	}
	if mode == entitlements.ModeOff && c.deployment() == extension.DeploymentProduction {
		errs = append(errs, errors.New(errDeploymentConfig+"production refuses billing.mode off"))
	}
	if c.Billing.RequirePlan && mode != entitlements.ModeExternal {
		errs = append(errs, errors.New("billing.require_plan needs billing.mode external"))
	}
	if c.Signup.SelfServe && mode == entitlements.ModeLicence {
		errs = append(errs, errors.New("signup.self_serve needs billing.mode external or off"))
	}
	for name, n := range map[string]int{
		"signup.max_orgs_per_account": c.Signup.MaxOrgsPerAccount, "signup.max_unplanned_per_account": c.Signup.MaxUnplannedPerAccount,
		"signup.per_account_per_hour": c.Signup.PerAccountPerHour, "signup.per_ip_per_hour": c.Signup.PerIPPerHour,
	} {
		if n < 0 || n > 1000 {
			errs = append(errs, fmt.Errorf("%s must be 0 (default) to 1000", name))
		}
	}
	if !versionPattern.MatchString(c.Signup.TermsVersion) || !versionPattern.MatchString(c.Signup.DPAVersion) {
		errs = append(errs, errors.New("signup.terms_version and signup.dpa_version must be short version names"))
	}
	return errs
}
