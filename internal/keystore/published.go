// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// PublishedKey is the public half of a platform signing key and its
// lifecycle, as the well-known documents list it (PAP-1 §11).
type PublishedKey struct {
	KID       string
	Purpose   keys.Purpose
	Algorithm keys.Algorithm
	// Public is the stored public key: 32 bytes (EdDSA), PKIX DER (ES256)
	// or the FIPS 204 encoding (ML-DSA-65).
	Public []byte
	State  keys.State
	// Created is when the key was created; Changed is when it last changed
	// state (became RETIRING, or REVOKED).
	Created, Changed time.Time
}

// PublishedKeys lists the platform signing keys of purposes, revoked ones
// included, oldest first. It reads no private material.
func PublishedKeys(ctx context.Context, pool *db.Pool, purposes []keys.Purpose) ([]PublishedKey, error) {
	names := make([]string, len(purposes))
	for i, p := range purposes {
		names[i] = string(p)
	}
	var out []PublishedKey
	err := pool.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPublishedKeys(ctx, ids.PlatformOrg, names)
		if err != nil {
			return err
		}
		out = make([]PublishedKey, len(rows))
		for i, r := range rows {
			out[i] = PublishedKey{
				KID: r.Kid, Purpose: keys.Purpose(r.Purpose), Algorithm: keys.Algorithm(r.Algorithm), Public: r.PublicKey,
				State: keys.State(r.State), Created: r.CreatedAt, Changed: r.StateChangedAt,
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
