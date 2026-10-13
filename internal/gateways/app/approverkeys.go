// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/authn/cose"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ApproverKey is one person's active security key, as the approver keys
// file of a customer-hosted gateway pins it (HR-038): the WebAuthn
// credential id, the public key as DER PKIX with its COSE algorithm, and
// its fingerprint for review.
type ApproverKey struct {
	ID, User           ids.UUID
	Email, DisplayName string
	Name               string
	CredentialID       []byte
	Algorithm          int
	PublicKey          []byte
	Fingerprint        string
	CreatedAt          time.Time
}

// ListApproverKeys pages through the active security keys of the org's
// enabled people (gateway.read), by key id. Everyone with a key is listed,
// because a step-up is made by the run's launcher or principal, who need
// not hold an approval role; the server still decides who counts, and the
// gateway only checks that each counted assertion was signed by a key its
// operator pinned. It returns the org, which the file names.
func (s *Service) ListApproverKeys(ctx context.Context, size int32, token string) ([]ApproverKey, ids.OrgID, string, error) {
	c, err := s.manager(ctx, td.PermGatewayRead)
	if err != nil {
		return nil, ids.OrgID{}, "", err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return nil, ids.OrgID{}, "", err
	}
	var rows []dbq.ApproverKeysRow
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err = dbq.New(tx).ApproverKeys(ctx, c.Org, pr.After, pr.Limit())
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, ids.OrgID{}, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.ApproverKeysRow) ids.UUID { return r.ID })
	out := make([]ApproverKey, 0, len(rows))
	for _, r := range rows {
		alg, der, err := cose.PKIX(r.PublicKey)
		if err != nil {
			// Registration accepts only keys this converts (HR-153).
			return nil, ids.OrgID{}, "", fmt.Errorf("gateways: security key %s: %w", r.ID, err)
		}
		out = append(out, ApproverKey{
			ID: r.ID, User: r.UserID, Email: r.Email, DisplayName: r.DisplayName, Name: r.Name, CredentialID: r.CredentialID,
			Algorithm: alg, PublicKey: der, Fingerprint: proof.Fingerprint(der), CreatedAt: r.CreatedAt,
		})
	}
	return out, c.Org, next, nil
}
