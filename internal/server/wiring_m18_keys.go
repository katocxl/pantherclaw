// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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
