// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package rollout

import (
	"context"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The VERIFIED gate (G0 M18 D154; F602, HR-479). A rollout started with a
// threshold of 1 to 100 percent completes only while at least that share
// of its targets other than EXCEPTION are VERIFIED; with no such target it
// cannot complete. The threshold is fixed when the rollout starts. The
// database checks it again on the stage change (00222), so a publish of
// the version made any other way is held to it too. No waves.

// Bounds of the threshold.
const (
	MinVerifiedPercent = 1
	MaxVerifiedPercent = 100
)

// Errors of the gate.
var (
	ErrVerifiedPercent = pcerr.New(pcerr.InvalidArgument, "POLICY_ROLLOUT_VERIFIED_PERCENT",
		"a verified threshold is 1 to 100 percent of the rollout's targets")
	ErrNotVerified = pcerr.New(pcerr.FailedPrecondition, "POLICY_ROLLOUT_NOT_VERIFIED",
		"too few of the rollout's targets are verified for its threshold; resolve the others or exclude them first")
)

// VerifiedThresholdMet reports whether target counts by state meet a
// threshold in percent: verified ≥ percent of every target that is not
// EXCEPTION, and at least one such target.
func VerifiedThresholdMet(counts map[string]int64, percent int32) bool {
	var counted int64
	for state, n := range counts {
		if state != TargetException {
			counted += n
		}
	}
	return counted > 0 && counts[TargetVerified]*100 >= counted*int64(percent)
}

// verifiedGate returns ErrNotVerified, with the counts, unless the
// rollout has no threshold or its targets meet it now.
func verifiedGate(ctx context.Context, q *dbq.Queries, org ids.OrgID, r dbq.PcPolicyRollout) error {
	if r.RequireVerifiedPercent == nil {
		return nil
	}
	rows, err := q.CountRolloutTargets(ctx, org, r.ID)
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	var counted int64
	for _, n := range rows {
		counts[n.State] = n.N
		if n.State != TargetException {
			counted += n.N
		}
	}
	if VerifiedThresholdMet(counts, *r.RequireVerifiedPercent) {
		return nil
	}
	// The same code and reason as ErrNotVerified (errors.Is matches it).
	return pcerr.New(pcerr.FailedPrecondition, ErrNotVerified.Reason(), fmt.Sprintf(
		"%d of %d targets other than EXCEPTION are verified, below the rollout's %d%% threshold; resolve the others or exclude them first",
		counts[TargetVerified], counted, *r.RequireVerifiedPercent))
}
