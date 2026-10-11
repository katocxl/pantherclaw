// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// warnApproverKeys says at start whether approved actions can be
// dispatched (HR-038): without a loadable approver keys file every action
// whose permit carries an approval is refused as approval_unverified.
func warnApproverKeys(ctx context.Context, cfg *Config, org string, log *slog.Logger) {
	k, err := proof.NewPinned(cfg.Approvals.ApproverKeysFile, org).Keys()
	if err != nil {
		log.WarnContext(ctx, "gateway.approver_keys_unavailable", slog.String("file", cfg.Approvals.ApproverKeysFile), pclog.Err(err))
		return
	}
	log.InfoContext(ctx, "gateway.approver_keys", slog.String("file", cfg.Approvals.ApproverKeysFile), slog.Int("keys", k.Len()),
		slog.String("rp_id", k.RPID))
}
