// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "tenancy.". The ledger stores each as "audit." + the kind.
const (
	TenancyBusinessUnitArchived = "tenancy.business_unit_archived"
	TenancyBusinessUnitCreated = "tenancy.business_unit_created"
	TenancyBusinessUnitUpdated = "tenancy.business_unit_updated"
	TenancyEnvironmentArchived = "tenancy.environment_archived"
	TenancyEnvironmentCreated = "tenancy.environment_created"
	TenancyEnvironmentUpdated = "tenancy.environment_updated"
	TenancyOrgCreated = "tenancy.org_created"
	TenancyOrgUpdated = "tenancy.org_updated"
	TenancyTeamArchived = "tenancy.team_archived"
	TenancyTeamCreated = "tenancy.team_created"
	TenancyTeamMemberAdded = "tenancy.team_member_added"
	TenancyTeamMemberRemoved = "tenancy.team_member_removed"
	TenancyTeamUpdated = "tenancy.team_updated"
	TenancyTermsAccepted = "tenancy.terms_accepted"
)
