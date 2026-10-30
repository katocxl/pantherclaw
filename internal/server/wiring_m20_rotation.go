// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// wireM20Rotation lets the credentials service rotate a GitHub App key
// (G0 M20 S20c, D253, D259): a rotation request confirms the credential
// preview's digest (HR-252), and the verification store leases its tests
// and confirmations to the connection's gateway with the sealed key
// attached.
func wireM20Rotation(pool *db.Pool, m6 *m6Services, verification *txapp.Service, bill *billing.Service) {
	c := responseContainment(pool, nil, bill)
	m6.credentials.WithRotations(func(ctx context.Context, tx db.TenantTx, connection ids.UUID, version int32) ([]byte, error) {
		p, err := c.PreviewCredentialIn(ctx, tx, connection, version)
		return p.Digest, err
	})
	if st, ok := verification.Store.(*pgtransactions.Store); ok {
		st.Rotations = m6.credentials
	}
}
