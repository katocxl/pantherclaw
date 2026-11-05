// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package anchors

import (
	"context"
	"errors"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	"github.com/katocxl/pantherclaw/internal/payments/httpsig"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// VerifyAgentSignature checks the RFC 9421 agent signature of a request a
// merchant backend received (D1123; HR-838): payments.read, Business. Keys
// come only from the org's ACTIVE AGENT_DIRECTORY anchors, and a nonce is
// accepted once per anchor. Every check is audited
// payments.agent_signature_checked.
func (s *Service) VerifyAgentSignature(ctx context.Context, req httpsig.Request) (httpsig.Result, error) {
	c, err := reader(ctx)
	if err != nil {
		return httpsig.Result{}, err
	}
	if err := s.business(ctx); err != nil {
		return httpsig.Result{}, err
	}
	if len(req.Body) > httpsig.MaxBody {
		return httpsig.Result{}, ErrInvalid
	}
	res, err := s.ForOrg(ctx, c.Org)
	if err != nil {
		return httpsig.Result{}, err
	}
	out, err := httpsig.Verify(ctx, req, res, nonces{pool: s.pool, org: c.Org}, s.clock.Now())
	if errors.Is(err, ap2.ErrLiveRefused) {
		return httpsig.Result{}, s.refuseLive(ctx, c, "agent_signature", ap2.KindAgentDirectory, "", nil)
	}
	if err != nil {
		return httpsig.Result{}, err
	}
	details := map[string]string{"valid": boolString(out.Valid), "authority": req.Authority}
	for k, v := range map[string]string{"reason": out.Reason, "tag": out.Tag, "keyid": out.KeyID} {
		if v != "" {
			details[k] = v
		}
	}
	if !out.AnchorID.IsZero() {
		details["anchor"] = out.AnchorID.String()
	}
	outcome := audit.Success
	if !out.Valid {
		outcome = audit.Denied
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return record(ctx, tx, c.Actor(), auditkind.PaymentsAgentSignatureChecked, out.AnchorID, outcome, "", details)
	})
	if err != nil {
		return httpsig.Result{}, err
	}
	return out, nil
}

// nonces is the nonce cache of one org (pc.payment_sig_nonces): rows older
// than 10 minutes are pruned before each insert.
type nonces struct {
	pool *db.Pool
	org  ids.OrgID
}

// Use implements httpsig.Nonces.
func (n nonces) Use(ctx context.Context, anchor ids.UUID, nonce string) (bool, error) {
	var fresh bool
	err := n.pool.InTenantTx(ctx, n.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.PrunePaymentSigNonces(ctx, n.org); err != nil {
			return err
		}
		rows, err := q.UsePaymentSigNonce(ctx, n.org, anchor, nonce)
		fresh = rows == 1
		return err
	})
	return fresh, err
}
