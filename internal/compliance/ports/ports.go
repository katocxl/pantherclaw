// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is what compliance coverage reads beyond the database (G0
// M25 D312).
package ports

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Campaign step outcomes, as the server derived them from its own
// transactions (D309).
const (
	OutcomeHeld              = "HELD"
	OutcomeDenied            = "DENIED"
	OutcomeNotRoutedReported = "NOT_ROUTED_REPORTED"
	OutcomeAllowed           = "ALLOWED"
	OutcomeNotExercised      = "NOT_EXERCISED"
)

// CampaignStep is one step of a finished campaign that ran in the period.
type CampaignStep struct {
	Campaign ids.UUID
	// Tags are the OWASP agentic risks of the step's scenario, as the
	// server's scenario library has them.
	Tags    []string
	Outcome string
}

// CampaignResults reads finished campaign results. The caller must already
// have read permission: coverage checks redteam.read before calling.
// Truncated says there were more than the source returned.
type CampaignResults interface {
	CampaignSteps(ctx context.Context, org ids.OrgID, start, end time.Time) (steps []CampaignStep, truncated bool, err error)
}
