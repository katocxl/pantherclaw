// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgwaitlist

import (
	"context"
	"time"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// OpenAutomationGate opens the AUTOMATION_GATE entry of a gate (G0 M11 part
// 2 D25, D25a, D62). Its subject is the gate's approval request, its
// requester the automation, it may have no agent, it shares the request's
// deadline and it ends with the request.
func OpenAutomationGate(ctx context.Context, tx db.TenantTx, org ids.OrgID, request, automation ids.UUID, step string,
	deadline time.Time, actor evdomain.Actor,
) (ids.UUID, error) {
	return open(ctx, tx, org, entry{
		kind: wdomain.KindAutomationGate, subjectType: "approval_request", subject: request, automation: &automation,
		deadline: deadline, trusted: map[string]string{"automation": automation.String(), "step": step},
	}, actor)
}
