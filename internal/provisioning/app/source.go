// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Source lists, in the posture queue, every active API key made by a person
// SCIM deprovisioned (D409 point 4). Deprovisioning ends sessions at once
// but leaves keys working, since revoking them could stop production: each
// such key is an owned finding until a person rotates or revokes it. It
// works in every edition, like deprovisioning.
type Source struct{ Pool *db.Pool }

var _ ports.Source = Source{}

// Name implements ports.Source.
func (Source) Name() pvdomain.Source { return pvdomain.SourceProvisioning }

// Findings implements ports.Source. A key names a service account and no
// agent, so the viewer needs org scope under posture.read and
// service_account.read.
func (s Source) Findings(ctx context.Context, v ports.Viewer, _ pvdomain.Filter) ([]pvdomain.Finding, bool, error) {
	reach := v.Posture
	if v.Under != nil {
		r, err := v.Under(ctx, td.PermServiceAccountRead)
		if err != nil {
			return nil, false, err
		}
		reach = reach.Intersect(r)
	}
	if !reach.Org {
		return nil, false, td.ErrPermissionDenied(td.PermServiceAccountRead) // RESTRICTED, never empty
	}
	var rows []dbq.ActiveKeysOfDeprovisionedRow
	err := s.Pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rows, err = dbq.New(tx).ActiveKeysOfDeprovisioned(ctx, v.Org, pvdomain.MaxPerSource+1)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, false, err
	}
	more := len(rows) > pvdomain.MaxPerSource
	if more {
		rows = rows[:pvdomain.MaxPerSource]
	}
	out := make([]pvdomain.Finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, pvdomain.Finding{
			Source: pvdomain.SourceProvisioning, SourceID: r.ID.String(), Kind: pvdomain.KindDeprovisionedOwnerKey,
			RootCause: "user:" + r.UserID.String(), Title: "An API key made by a deprovisioned person is still active",
			Detail: map[string]string{"key_name": r.Name, "hint": r.Hint, "service_account_id": r.ServiceAccountID.String()},
			State:  "OPEN", Since: r.DeprovisionedAt,
			Fix: pvdomain.Fix{
				Kind: pvdomain.FixRotateSecret, TargetID: "service_account:" + r.ServiceAccountID.String(),
				Label: "Rotate or revoke the key",
			},
		})
	}
	return out, more, nil
}
