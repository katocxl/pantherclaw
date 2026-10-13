// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
)

// approval is what the permit of an approval-based ALLOW carries (HR-038,
// founder decision 2026-10-10): the binding, its canonical input, and the
// assertion of every approver who counts, so a customer-hosted gateway
// verifies the approval against the keys it pinned before BeginDispatch.
// Any other evaluation carries none.
func (a *Authority) approval(ctx context.Context, gw Gateway, ev *pipeline.Evaluation) (*proof.Approval, error) {
	h := ev.Hold
	if h == nil || !h.Satisfied || h.Request == nil || ev.MonitorPermit() {
		return nil, nil //nolint:nilnil // no approval
	}
	as, err := a.Store.ApprovalProof(ctx, gw.Org, h.Request.ID)
	if err != nil {
		return nil, err
	}
	return &proof.Approval{Binding: h.Binding.String(), Input: proof.B64(h.Binding.Input), Assertions: as}, nil
}
