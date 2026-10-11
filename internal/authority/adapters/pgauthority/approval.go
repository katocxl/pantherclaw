// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"slices"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ApprovalProof implements finalize.Store (HR-038): the stored assertion
// of every response that counts toward the request, with the WebAuthn
// credential id it was signed with and, for a batch approval, the sorted
// bindings of the batch whose hash it signed (PAP-1 §8).
func (s *Store) ApprovalProof(ctx context.Context, org ids.OrgID, request ids.UUID) ([]proof.Assertion, error) {
	var out []proof.Assertion
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ApprovalAssertions(ctx, org, request)
		if err != nil {
			return err
		}
		batches := map[ids.UUID][]string{}
		out = make([]proof.Assertion, 0, len(rows))
		for _, r := range rows {
			a := proof.Assertion{
				Requirement: int(r.Requirement), CredentialID: proof.B64(r.WebauthnID), AuthenticatorData: proof.B64(r.AuthenticatorData),
				ClientDataJSON: proof.B64(r.ClientDataJson), Signature: proof.B64(r.Signature),
			}
			if r.BatchID != nil {
				b, ok := batches[*r.BatchID]
				if !ok {
					bindings, err := q.BatchBindings(ctx, org, *r.BatchID)
					if err != nil {
						return err
					}
					for _, x := range bindings {
						b = append(b, proof.B64(x))
					}
					slices.Sort(b)
					batches[*r.BatchID] = b
				}
				a.Batch = b
			}
			out = append(out, a)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
