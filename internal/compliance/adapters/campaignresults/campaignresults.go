// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package campaignresults turns finished campaigns into the steps compliance
// coverage counts (G0 M25 D304, D312). Outcomes are the ones the server
// derived; tags come only from the server's own library.
package campaignresults

import (
	"context"
	"time"

	cports "github.com/katocxl/pantherclaw/internal/campaigns/ports"
	"github.com/katocxl/pantherclaw/internal/compliance/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
)

// Reader adapts the campaign read port.
type Reader struct {
	Results cports.ResultReader
	// Tags gives a scenario's risks as the server's library has them. A
	// scenario it does not know has none and counts for no control.
	Tags func(scenario string) []string
}

// LibraryTags reads a scenario's risks from the server's library.
func LibraryTags(scenario string) []string {
	e, ok := library.Lookup(scenario)
	if !ok {
		return nil
	}
	return e.ASI
}

// CampaignSteps implements ports.CampaignResults. A truncated read stays
// truncated, so coverage shows a gap and never a silent cut.
func (r Reader) CampaignSteps(ctx context.Context, org ids.OrgID, start, end time.Time) ([]ports.CampaignStep, bool, error) {
	res, err := r.Results.CampaignResults(ctx, org, cports.Filter{Start: start, End: end})
	if err != nil {
		return nil, false, err
	}
	var out []ports.CampaignStep
	for _, item := range res.Items {
		for _, st := range item.Steps {
			out = append(out, ports.CampaignStep{Campaign: item.Campaign.ID, Tags: r.Tags(st.Scenario), Outcome: string(st.Outcome)})
		}
	}
	return out, res.Truncated, nil
}
