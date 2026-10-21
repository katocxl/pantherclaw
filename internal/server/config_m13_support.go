// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/support"
)

// SupportConfig is customer-approved support access (G0 M13 D32, D38):
// the operator's staff org and the accounts of its support staff. Empty
// turns support access off; a self-hosted server (billing mode licence)
// refuses it.
type SupportConfig struct {
	// StaffOrg is the org whose users are the support staff (created by
	// the operator).
	StaffOrg string `json:"staff_org" env:"PC_SUPPORT_STAFF_ORG"`
	// StaffAccounts are the staff members' hosted accounts, by issuer and
	// subject; a staff org user counts as staff only when their linked
	// account is listed.
	StaffAccounts []support.Identity `json:"staff_accounts"`
}

// maxStaffAccounts bounds the staff list.
const maxStaffAccounts = 200

// support returns the support service's configuration.
func (c *Config) support() support.Config {
	org, err := ids.Parse[ids.Org](c.Support.StaffOrg)
	if err != nil || len(c.Support.StaffAccounts) == 0 {
		return support.Config{}
	}
	return support.Config{StaffOrg: org, Staff: c.Support.StaffAccounts}
}

// validateSupport checks the staff configuration.
func (c *Config) validateSupport() []error {
	s := c.Support
	if s.StaffOrg == "" && len(s.StaffAccounts) == 0 {
		return nil
	}
	var errs []error
	if org, err := ids.Parse[ids.Org](s.StaffOrg); err != nil || org == ids.PlatformOrg {
		errs = append(errs, errors.New("support.staff_org must be an organization id"))
	}
	if len(s.StaffAccounts) == 0 || len(s.StaffAccounts) > maxStaffAccounts {
		errs = append(errs, errors.New("support.staff_accounts must list 1 to 200 accounts"))
	}
	for _, a := range s.StaffAccounts {
		if a.Issuer == "" || len(a.Issuer) > 512 || a.Subject == "" || len(a.Subject) > 255 {
			errs = append(errs, errors.New("support.staff_accounts entries need an issuer and a subject"))
			break
		}
	}
	if c.billingMode() == entitlements.ModeLicence {
		errs = append(errs, errors.New("support access is for hosted servers: it needs billing.mode external or off"))
	}
	return errs
}
