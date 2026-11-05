// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package partners

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Customer is one customer of an ACTIVE link with counts only (HR-816).
type Customer struct {
	Org              ids.UUID
	Name             string
	Link             ids.UUID
	LinkEndsAt       time.Time
	WaitingApprovals int64
	OpenAlerts       int64
	LastDecisionAt   *time.Time
}

// Customers is the partner's cross-customer view (D1101; D1100a Q2): for
// each ACTIVE link, read in the partner org's own tenant through the link
// policy, one transaction in that customer's tenant first records
// partner.summary_read there, then reads the customer's name and counts.
// It needs partner.read in the partner org (never from a partner
// session) and the partner org on Enterprise.
func (s *Service) Customers(ctx context.Context) ([]Customer, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	if c.Partner() {
		return nil, ErrPartnerSide
	}
	if err := s.partnerAccess(ctx, c.Org); err != nil {
		return nil, err
	}
	var links []dbq.ActivePartnerLinksOfPartnerRow
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		links, err = dbq.New(tx).ActivePartnerLinksOfPartner(ctx, c.Org.UUID())
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	actor := c.Actor()
	if c.Human() {
		actor = partnerActor(c.Org.UUID(), c.Principal.ID)
	}
	out := make([]Customer, 0, len(links))
	for _, l := range links {
		customer, err := ids.FromUUID[ids.Org](l.CustomerOrg)
		if err != nil || l.EndsAt == nil {
			continue
		}
		cu := Customer{Org: l.CustomerOrg, Link: l.ID, LinkEndsAt: *l.EndsAt}
		err = s.pool.InTenantTx(ctx, customer, func(ctx context.Context, tx db.TenantTx) error {
			q := dbq.New(tx)
			// The link must still be in force, as the customer sees it.
			live, err := q.LivePartnerLink(ctx, c.Org.UUID(), l.CustomerOrg)
			if db.IsNoRows(err) || (err == nil && live.ID != l.ID) {
				cu.Link = ids.UUID{}
				return nil
			} else if err != nil {
				return err
			}
			if err := record(ctx, tx, actor, auditkind.PartnerSummaryRead, "partner_link", l.ID, map[string]string{
				"partner_org": c.Org.String(),
			}); err != nil {
				return err
			}
			sum, err := q.PartnerCustomerSummary(ctx, customer)
			if err != nil {
				return err
			}
			cu.Name, cu.WaitingApprovals, cu.OpenAlerts = sum.Name, sum.WaitingApprovals, sum.OpenAlerts
			if sum.LastDecisionAt.Unix() > 0 {
				at := sum.LastDecisionAt
				cu.LastDecisionAt = &at
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if !cu.Link.IsZero() {
			out = append(out, cu)
		}
	}
	return out, nil
}
