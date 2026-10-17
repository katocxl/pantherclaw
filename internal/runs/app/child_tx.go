// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// StartChildRunTx is StartChildRun inside the caller's transaction (G0 M14
// D89): the Authority starts a peer agent's child run of a requester's run
// inside BeginDispatch's transaction. The checks are StartChildRun's: the
// parent bound to the calling instance and active (locked), the depth, a
// usable agent, the simulation rule, the label and a lifetime within the
// parent's.
func StartChildRunTx(ctx context.Context, tx db.TenantTx, in ChildInput) (Run, error) {
	if in.TTL == 0 {
		in.TTL = MaxTTL
	}
	minutes, err := checkLabel(in.TaskRef, in.TTL)
	if err != nil {
		return Run{}, err
	}
	if in.Caller.Org != tx.OrgID() {
		return Run{}, ErrRunNotFound
	}
	return startChildRunTx(ctx, tx, in, minutes)
}
