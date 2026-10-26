// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package datarequests implements organisation exports and verified deletion.
package datarequests

// exportTable is an explicit projection, not a deny-list. Adding a column
// to the database never silently adds it to an export.
type exportTable struct {
	Name    string
	Columns []string
}

var exportTables = []exportTable{
	{"business_units", []string{"org_id", "id", "slug", "name", "description", "state", "created_at", "updated_at"}},
	{"teams", []string{"org_id", "id", "business_unit_id", "slug", "name", "description", "state", "created_at", "updated_at"}},
	{"environments", []string{"org_id", "id", "team_id", "slug", "name", "description", "kind", "state", "created_at", "updated_at"}},
	{"users", []string{"org_id", "id", "issuer", "subject", "email", "display_name", "state", "created_at", "updated_at", "last_login_at"}},
	{"memberships", []string{"org_id", "id", "team_id", "user_id", "created_at"}},
	{"role_bindings", []string{"org_id", "id", "role", "user_id", "service_account_id", "scope_type", "business_unit_id", "team_id", "environment_id", "created_by", "created_at"}},
	{"service_accounts", []string{"org_id", "id", "name", "description", "state", "created_by", "created_at", "updated_at"}},
	{"agents", []string{"org_id", "id", "name", "purpose", "team_id", "environment_id", "owner_user_id", "backup_owner_user_id", "execution_context", "state", "created_by", "created_at", "updated_at", "claimed_at", "retired_at"}},
	{"runs", []string{"org_id", "id", "agent_id", "instance_id", "environment_id", "principal_user_id", "principal_sa_id", "parent_run_id", "grant_id", "task_ref", "state", "end_reason", "created_at", "expires_at", "ended_at"}},
	{"grants", []string{"org_id", "id", "agent_id", "instance_id", "principal_user_id", "principal_sa_id", "environment_id", "parent_id", "depth", "state", "current_revision", "grantor_kind", "grantor_id", "basis", "created_at", "revoked_at", "revoke_reason"}},
	{"connections", []string{"org_id", "id", "name", "kind", "gateway_id", "package", "destination_class", "access_mode", "default_mode", "state", "revision", "created_by", "created_at", "updated_by", "updated_at"}},
	{"policies", []string{"org_id", "id", "bundle_id", "created_at"}},
	{"policy_versions", []string{"org_id", "id", "policy_id", "version", "bundle", "state", "created_by", "created_at", "published_by", "published_at"}},
	{"grant_revisions", []string{"org_id", "id", "grant_id", "revision", "task_ref", "not_before", "expires_at", "bounds", "requirements", "limits", "delegation_depth", "max_children", "min_attestation", "created_by", "created_at"}},
	{"action_definitions", []string{"org_id", "id", "version_id", "operation", "digest", "canonical"}},
	{"package_versions", []string{"org_id", "id", "package_id", "version", "file_digest", "raw", "state", "imported_at", "changed_at"}},
	{"envelope_revisions", []string{"org_id", "id", "envelope_id", "revision", "name", "bounds", "requirements", "limits", "max_depth", "max_children", "max_root_lifetime_s", "repeat_window_s", "min_attestation", "created_by", "created_at"}},
	{"cases", []string{"org_id", "id", "title", "source", "opened_by_type", "opened_by_id", "alert_id", "incident_id", "state", "owner_id", "disposition", "impact", "created_at", "updated_at", "closed_at"}},
	{"tool_packages", []string{"org_id", "id", "name", "created_at"}},
	{"org_entitlements", []string{"org_id", "plan_id", "edition", "status", "source", "period_end", "comp_until", "version", "lapsed_at", "created_at", "updated_at"}},
}
