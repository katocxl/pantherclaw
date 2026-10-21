// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// ErrPlanLimit reports a creation the org's plan does not allow (G0 UI D9,
// HR-360).
var ErrPlanLimit = pcerr.New(pcerr.FailedPrecondition, "PLAN_LIMIT", "the organization's plan allows no more of these")

// checkEnvironmentLimit enforces the plan's environment limit (HR-360).
// Creations of one org are serialized by a transaction advisory lock.
func checkEnvironmentLimit(ctx context.Context, ents Entitlements, q *dbq.Queries, org ids.OrgID) error {
	if ents == nil {
		return nil
	}
	ent, err := ents.Current(ctx)
	if err != nil {
		return err
	}
	if ent.Limits.MaxEnvironments == billing.Unlimited {
		return nil
	}
	if err := q.LockAgentLimit(ctx, "environments:"+org.String()); err != nil {
		return err
	}
	n, err := q.CountActiveEnvironments(ctx, org)
	if err != nil {
		return err
	}
	return limitError(ent.CheckEnvironments(int(n)))
}

// checkMemberLimit enforces the plan's member limit for a new invitation:
// active members and pending invitations count (HR-360).
func checkMemberLimit(ctx context.Context, ents Entitlements, q *dbq.Queries, org ids.OrgID) error {
	if ents == nil {
		return nil
	}
	ent, err := ents.Current(ctx)
	if err != nil {
		return err
	}
	if ent.Limits.MaxMembers == billing.Unlimited {
		return nil
	}
	if err := q.LockAgentLimit(ctx, "members:"+org.String()); err != nil {
		return err
	}
	members, err := q.CountActiveMembers(ctx, org)
	if err != nil {
		return err
	}
	pending, err := q.CountPendingMemberInvitations(ctx, org)
	if err != nil {
		return err
	}
	return limitError(ent.CheckMembers(int(members + pending)))
}

func limitError(err error) error {
	if errors.Is(err, billing.ErrLimitReached) {
		return pcerr.Wrap(err, pcerr.FailedPrecondition, "PLAN_LIMIT", err.Error())
	}
	return err
}

// WithEntitlements makes invitations count against the org's member limit
// (HR-360).
func (a *Access) WithEntitlements(ents Entitlements) *Access {
	a.ents = ents
	return a
}
