// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package campaignresults turns finished campaigns into the steps compliance
// coverage counts (G0 M25 D304, D312). Outcomes are the ones the server
// derived; tags come only from the server's own library, and only for a
// campaign whose declared set is the library's (D531 L2).
package campaignresults

import (
	"context"
	"time"

	cdomain "github.com/katocxl/pantherclaw/internal/campaigns/domain"
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
	// Digest gives the library's digest of a campaign scenario. A campaign
	// whose set digest is not the library's for its scenarios counts for no
	// control: its steps keep their outcomes but carry no tag.
	Digest func(scenario string) (string, bool)
}

// LibraryTags reads a scenario's risks from the server's library: a
// campaign's from its campaign file, any other's from its scenario file.
func LibraryTags(scenario string) []string {
	if tags := library.CampaignASI(scenario); tags != nil {
		return tags
	}
	e, ok := library.Lookup(scenario)
	if !ok {
		return nil
	}
	return e.ASI
}

// LibraryDigest reads a campaign scenario's digest from the server's library.
func LibraryDigest(scenario string) (string, bool) {
	e, ok := library.Campaign(scenario)
	return e.Digest, ok
}

// Library is the reader the server wires: tags and digests from its library.
func Library(results cports.ResultReader) Reader {
	return Reader{Results: results, Tags: LibraryTags, Digest: LibraryDigest}
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
		known := r.libraryDigest(item.Campaign)
		for _, st := range item.Steps {
			var tags []string
			if known {
				tags = r.Tags(st.Scenario)
			}
			out = append(out, ports.CampaignStep{Campaign: item.Campaign.ID, Tags: tags, Outcome: string(st.Outcome)})
		}
	}
	return out, res.Truncated, nil
}

// libraryDigest reports whether the campaign declared exactly the library's
// scenarios at the library's digests.
func (r Reader) libraryDigest(c cdomain.Campaign) bool {
	if r.Digest == nil || len(c.Scenarios) == 0 {
		return false
	}
	set := make([]cdomain.Declared, 0, len(c.Scenarios))
	for _, id := range c.Scenarios {
		d, ok := r.Digest(id)
		if !ok {
			return false
		}
		set = append(set, cdomain.Declared{ID: id, Digest: d})
	}
	return cdomain.SetDigest(set) == c.SetDigest
}
