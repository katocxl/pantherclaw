// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// wireM20Rotation lets the credentials service rotate a GitHub App key
// (G0 M20 S20c, D253, D259, D274): a rotation request confirms the
// credential preview's digest (HR-252); the verification store leases its
// tests and confirmations to the connection's gateway with the sealed key
// attached; and every rotation change enqueues the org's exposure and
// posture recompute in its transaction, which raises or remediates
// unconfirmed_rotation.
func wireM20Rotation(pool *db.Pool, m6 *m6Services, verification *txapp.Service, bill *billing.Service, log *slog.Logger) {
	c := responseContainment(pool, nil, bill)
	m6.credentials.WithRotations(func(ctx context.Context, tx db.TenantTx, connection ids.UUID, version int32) ([]byte, error) {
		p, err := c.PreviewCredentialIn(ctx, tx, connection, version)
		return p.Digest, err
	})
	if st, ok := verification.Store.(*pgtransactions.Store); ok {
		st.Rotations = m6.credentials
	}
	m6.credentials.OnRotationChange(rotationRecompute(pool, log))
}

// rotationRecompute enqueues the org's recompute in the rotation's
// transaction. Its insert-only job client is built on the first change:
// start-up's gate on that client is the security steps' (D115 R3, D120),
// which every role builds after this wiring. A client that still cannot be
// built fails the change, so no rotation commits without its recompute.
func rotationRecompute(pool *db.Pool, log *slog.Logger) func(context.Context, db.TenantTx) error {
	client := sync.OnceValues(func() (*jobs.Client, error) { return insertJobClient(pool, log) })
	return func(ctx context.Context, tx db.TenantTx) error {
		insert, err := client()
		if err != nil {
			return fmt.Errorf("credential rotation: job client: %w", err)
		}
		return jobs.InsertTx(ctx, insert, tx, recompute.OrgArgs{Org: tx.OrgID()}, nil)
	}
}
