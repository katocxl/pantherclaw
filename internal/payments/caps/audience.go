// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package caps

import (
	"context"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// AgentPayPackage is the package whose connections carry a merchant
// audience.
const AgentPayPackage = "pc.agentpay"

var audienceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)

// ErrNotAgentPay is a connection that is not a pc.agentpay connection.
var ErrNotAgentPay = pcerr.New(pcerr.FailedPrecondition, "NOT_AGENTPAY_CONNECTION",
	"only a pc.agentpay connection has a merchant audience")

// ErrConnectionNotFound is an unknown connection.
var ErrConnectionNotFound = pcerr.New(pcerr.NotFound, "CONNECTION_NOT_FOUND", "connection not found")

// SetMerchantAudience sets the audience a pc.agentpay connection's
// mandates must name (G0 M39 D1124c): the server pins it when it verifies
// them (ap2.WithAudiences). A person only, Business edition; audited
// payments.audience_set.
func (s *Service) SetMerchantAudience(ctx context.Context, connection ids.UUID, audience string) error {
	c, err := person(ctx)
	if err != nil {
		return err
	}
	if err := s.business(ctx); err != nil {
		return err
	}
	if !audienceRe.MatchString(audience) {
		return ErrInvalid
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, connection)
		if db.IsNoRows(err) {
			return ErrConnectionNotFound
		} else if err != nil {
			return err
		}
		if conn.Package != AgentPayPackage {
			return ErrNotAgentPay
		}
		if err := q.SetConnectionMerchantAudience(ctx, dbq.SetConnectionMerchantAudienceParams{
			OrgID: c.Org, ConnectionID: connection, MerchantAudience: audience, UpdatedBy: c.Principal.ID.String(),
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.PaymentsAudienceSet, Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "connection", ID: connection.String()},
			Details: map[string]string{"merchant_audience": audience},
		})
		return err
	})
}
