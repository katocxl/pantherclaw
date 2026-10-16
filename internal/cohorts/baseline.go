// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cohorts

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Errors of BaselineForAgent.
var (
	ErrAmbiguous  = pcerr.New(pcerr.FailedPrecondition, "COHORT_AMBIGUOUS", "the agent is in more than one cohort with a baseline")
	ErrNoBaseline = pcerr.New(pcerr.FailedPrecondition, "NO_BASELINE", "the agent is in no cohort with a baseline")
)

// BaselineForAgent returns, in tx, the baseline of the one cohort with a
// baseline the agent belongs to (a static member or a rule match), with
// that cohort's id, for a caller that already authorized the read (D115
// R2b). An agent in several such cohorts is COHORT_AMBIGUOUS, in none
// NO_BASELINE.
func BaselineForAgent(ctx context.Context, tx db.TenantTx, org ids.OrgID, agent ids.UUID) (Baseline, ids.UUID, error) {
	rows, err := dbq.New(tx).AgentBaselineCohorts(ctx, agent, org)
	switch {
	case err != nil:
		return Baseline{}, ids.UUID{}, err
	case len(rows) == 0:
		return Baseline{}, ids.UUID{}, ErrNoBaseline
	case len(rows) > 1:
		return Baseline{}, ids.UUID{}, ErrAmbiguous
	}
	c := cohortOf(rows[0], 0)
	if c.Baseline == nil {
		return Baseline{}, ids.UUID{}, ErrNoBaseline
	}
	return *c.Baseline, c.ID, nil
}
