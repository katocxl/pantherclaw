// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// newKeyProvider builds the server's KEK router from key_service and
// kek_files (D157): the configured kind wraps new keys, and each kek_id
// prefix routes an unwrap to its provider.
func newKeyProvider(cfg *Config) (*keys.Router, error) {
	return keys.FromConfig(cfg.KeyService, cfg.KEKFiles)
}
