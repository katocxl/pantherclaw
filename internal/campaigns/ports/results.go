// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is what other modules read of attack campaigns. Compliance
// evidence (G0 M25 D312) reads results through ResultReader; only the
// campaign modules know the tables.
package ports

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Filter picks finished campaigns: Start <= finish time < End, of one range
// agent when Agent is set.
type Filter struct {
	Start, End time.Time
	Agent      *ids.UUID
}

// MaxResults bounds one read; Truncated says more exist.
const MaxResults = 500

// Result is one finished campaign with its steps. Abandoned and open
// campaigns are never results: a run that never finished says nothing. A
// NotRoutedReported step is a report, and a NotExercised step a gap (D306).
type Result struct {
	Campaign domain.Campaign
	Steps    []domain.Step
	Counts   domain.Counts
}

// Results is one read of campaign results.
type Results struct {
	Items     []Result
	Truncated bool
}

// ResultReader reads an org's finished campaigns. It checks no permission:
// the caller reports on what its own caller may read, and treats what that
// caller cannot read as a gap.
type ResultReader interface {
	CampaignResults(ctx context.Context, org ids.OrgID, f Filter) (Results, error)
}
