// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// retentionUser returns database.retention_user or pc_retention.
func (c *Config) retentionUser() string {
	if c.DB.RetentionUser != "" {
		return c.DB.RetentionUser
	}
	return db.RoleRetention
}

// validateRetention keeps the retention job on a role of its own (G0 M7
// design decision 9, HR-198): never the application's or the migrator's.
func (c *Config) validateRetention() []error {
	u := c.retentionUser()
	if u == c.DB.AppUser || u == c.DB.MigratorUser || u == db.RoleApp || u == db.RoleMigrator || u == "postgres" {
		return []error{errors.New("database.retention_user must be the retention role (pc_retention), not the application's or the migrator's")}
	}
	if c.DB.RetentionPasswordFile != "" && c.DB.RetentionPasswordFile == c.DB.AppPasswordFile {
		return []error{errors.New("database.retention_password_file must be the retention role's own password file")}
	}
	return nil
}
