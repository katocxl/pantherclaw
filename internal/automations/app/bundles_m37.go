// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrBundleRevoked refuses enabling or resuming an automation a revoked
// publisher bundle drafted: revoked stays off (G0 M37 D1083a, HR-799).
var ErrBundleRevoked = pcerr.New(pcerr.FailedPrecondition, "BUNDLE_REVOKED",
	"the automation came from a revoked bundle and stays off")

// VoidBundleRevoked voids an enabling of such an automation.
const VoidBundleRevoked = "BUNDLE_REVOKED"

// bundleRevoked reports whether a REVOKED bundle item drafted the
// automation. It locks the item rows, so a revocation running at the same
// time waits; callers check before they lock the automation, the order a
// revocation takes them in.
func bundleRevoked(ctx context.Context, q *dbq.Queries, org ids.OrgID, automation ids.UUID) (bool, error) {
	states, err := q.LockBundleTargetStates(ctx, org, "automation", automation.String())
	if err != nil {
		return false, err
	}
	return slices.Contains(states, "REVOKED"), nil
}
