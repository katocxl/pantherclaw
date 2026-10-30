// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"log/slog"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// newKeyProvider builds the KEK router from key_service and kek_files
// (D157): the configured kind wraps new keys, and each kek_id prefix routes
// an unwrap to its provider. The server and every operator command
// (keys rotate-*, restore, dev seeding) use it (D165).
func newKeyProvider(cfg *Config) (*keys.Router, error) {
	return keys.FromConfig(cfg.KeyService, cfg.KEKFiles)
}

// newCheckedKeyProvider is newKeyProvider for the server's start: it also
// refuses to start when the platform's stored keys are under a KEK that no
// configured provider holds, with a configuration error instead of a
// later unwrap failure (D165).
func newCheckedKeyProvider(ctx context.Context, cfg *Config, pool *db.Pool) (*keys.Router, error) {
	kp, err := newKeyProvider(cfg)
	if err != nil {
		return nil, err
	}
	if err := keystore.CheckStoredKEKs(ctx, pool, ids.PlatformOrg, kp); err != nil {
		return nil, err
	}
	return kp, nil
}

// validateKeyService checks key_service and the keystore role's password
// file.
func (c *Config) validateKeyService() []error {
	errs := c.KeyService.Validate(len(c.KEKFiles))
	if f := c.DB.KeystorePasswordFile; f != "" && (f == c.DB.AppPasswordFile || f == c.DB.MigratorPasswordFile || f == c.DB.DeleterPasswordFile) {
		errs = append(errs, errors.New("database.keystore_password_file must be the keystore role's own password file"))
	}
	return errs
}

// registerKeyRewrap adds the hourly re-wrap job (00224): keys not under
// the current KEK move to it, verified before each write (HR-487), and
// stored KEKs no provider holds are reported (D170). The writes go through
// a separately authenticated pc_keystore pool (D171), opened only here by
// workers and closed by the returned func; without
// database.keystore_password_file the job reports KEY_REWRAP_UNCONFIGURED.
func registerKeyRewrap(ctx context.Context, reg *jobs.Registry, cfg *Config, pool *db.Pool, kp keys.KeyProvider, log *slog.Logger) (
	[]*river.PeriodicJob, func(), error,
) {
	closePool := func() {}
	var ks *db.Pool
	if cfg.DB.KeystorePasswordFile == "" {
		log.InfoContext(ctx, "key re-wrap needs the keystore role; keys stay under the KEK that wrapped them",
			slog.String("code", "KEY_REWRAP_UNCONFIGURED"))
	} else {
		c, err := cfg.dbConfig(db.RoleKeystore, cfg.DB.KeystorePasswordFile, 2)
		if err != nil {
			return nil, nil, err
		}
		if ks, err = db.Open(ctx, c); err != nil {
			return nil, nil, err
		}
		closePool = ks.Close
	}
	periodic, err := keystore.RegisterRewrap(reg, pool, ks, kp, log)
	if err != nil {
		closePool()
		return nil, nil, err
	}
	return periodic, closePool, nil
}
