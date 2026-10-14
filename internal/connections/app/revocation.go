// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ReportRevocationFailure records credential.revoke_failed for an
// installation token that gateway minted for a fact read, a verification
// read or an organization scan of connection id and could not revoke: it
// lasts until the expiry GitHub stated (ADR-0021 item 6, R-18). A
// dispatch's token is recorded with its outcome instead. The connection
// must be one the gateway serves (otherwise not found).
func (s *Service) ReportRevocationFailure(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, purpose string, installation int64,
	repository string, expires time.Time,
) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		conn, err := lock(ctx, dbq.New(tx), org, id)
		if err != nil {
			return err
		}
		if conn.GatewayID != gateway {
			return ErrNotFound
		}
		details := map[string]string{"purpose": purpose, "installation": strconv.FormatInt(installation, 10)}
		if repository != "" {
			details["repository"] = repository
		}
		if !expires.IsZero() {
			details["expires_at"] = expires.UTC().Format(time.RFC3339)
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "credential.revoke_failed", Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()}, Outcome: audit.Failure,
			Object: &audit.Object{Type: "connection", ID: id.String()}, Details: details,
		})
		return err
	})
}
