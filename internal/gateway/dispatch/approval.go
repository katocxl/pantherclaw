// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
)

// approved checks the approval a permit carries before anything is
// committed (HR-038, T-030; founder decision 2026-10-10, "pinned file,
// fail closed"): the binding must cover the requested action and the one
// the permit binds, and every counted approver's assertion must verify
// against a key the operator pinned. A permit without an approval is not
// checked; a gateway with no pinned keys refuses every one that has one.
func (e *Engine) approved(a *proof.Approval, requested, bound actionir.Parsed) error {
	if a == nil {
		return nil
	}
	if e.approvers == nil {
		return proof.ErrNoKeys
	}
	return e.approvers.Verify(a, proof.Want{ActionHash: requested.HashHex(), EffectiveHash: bound.HashHex()})
}
