// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/datarequests"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// BackupsConfig is the documented off-site backup retention, not a claim
// that deletion can erase already exported, immutable backup objects.
type BackupsConfig struct {
	RetentionDays int `json:"retention_days" env:"PC_BACKUPS_RETENTION_DAYS"`
}

func (c *Config) validateDataRequests() []error {
	var errs []error
	if c.Backups.RetentionDays < 0 || c.Backups.RetentionDays > 3650 {
		errs = append(errs, errors.New("backups.retention_days must be between 1 and 3650 (or zero for the default 60)"))
	}
	if c.DB.DeleterPasswordFile != "" && (c.DB.DeleterPasswordFile == c.DB.AppPasswordFile || c.DB.DeleterPasswordFile == c.DB.MigratorPasswordFile) {
		errs = append(errs, errors.New("database.deleter_password_file must be the deleter role's own password file"))
	}
	return errs
}

func newDataRequests(cfg *Config, pool *db.Pool, keyReg *keys.Registry, m5 *m5Services, log *slog.Logger) (*datarequests.Service, error) {
	retention := cfg.Backups.RetentionDays
	if retention == 0 {
		retention = 60
	}
	if retention < 1 || retention > 3650 {
		return nil, errors.New("backups.retention_days must be between 1 and 3650")
	}
	if cfg.DB.DeleterPasswordFile != "" && (cfg.DB.DeleterPasswordFile == cfg.DB.AppPasswordFile || cfg.DB.DeleterPasswordFile == cfg.DB.MigratorPasswordFile) {
		return nil, errors.New("database.deleter_password_file must be the deleter role's own password file")
	}
	insert, err := jobs.NewClient(pool, nil, jobs.Config{Logger: log})
	if err != nil {
		return nil, err
	}
	s := &datarequests.Service{Pool: pool, Keys: keyReg, Jobs: insert, Bundles: evapp.New(pool, cfg.logOrigin()), BackupRetentionDays: retention, Cosign: cfg.Evidence.MLDSACosign, LapseEnabled: cfg.billingMode() == entitlements.ModeExternal}
	if m5 != nil {
		s.Notify = m5.notifications
	}
	return s, nil
}

func registerDataRequests(rs *connect.Server, d apiDeps) {
	s := d.data
	if s == nil {
		s = &datarequests.Service{Pool: d.pool, Keys: d.reg, Bundles: evapp.New(d.pool, d.logOrigin)}
	}
	pantherclawv1connect.RegisterDataRequestServiceHandler(rs, datarequests.RPC{Service: s})
}

func mountDataRequests(mux *http.ServeMux, d apiDeps) {
	if d.web != nil && d.data != nil {
		datarequests.MountPages(mux, d.web, d.data)
	}
}

// The separately authenticated deletion pool is opened only by workers,
// and its owner closes it on every worker shutdown/error path.
func registerDataWorkers(ctx context.Context, reg *jobs.Registry, cfg *Config, s *datarequests.Service, log *slog.Logger) ([]*river.PeriodicJob, func(), error) {
	closePool := func() {}
	if cfg.DB.DeleterPasswordFile == "" {
		log.WarnContext(ctx, "organisation erasure is waiting for the dedicated deletion role", slog.String("code", "DATA_DELETER_UNCONFIGURED"))
	}
	if cfg.DB.DeleterPasswordFile != "" {
		c, err := cfg.dbConfig(db.RoleDeleter, cfg.DB.DeleterPasswordFile, 2)
		if err != nil {
			return nil, nil, err
		}
		p, err := db.Open(ctx, c)
		if err != nil {
			return nil, nil, err
		}
		s.Deleter = p
		closePool = p.Close
	}
	if err := datarequests.Register(reg, s); err != nil {
		closePool()
		return nil, nil, err
	}
	return datarequests.PeriodicJobs(), closePool, nil
}
