// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package campaignresults_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	cports "github.com/katocxl/pantherclaw/internal/campaigns/ports"
	"github.com/katocxl/pantherclaw/internal/compliance/adapters/campaignresults"
	"github.com/katocxl/pantherclaw/internal/compliance/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
)

type fake struct {
	res cports.Results
	err error
	got cports.Filter
}

func (f *fake) CampaignResults(_ context.Context, _ ids.OrgID, flt cports.Filter) (cports.Results, error) {
	f.got = flt
	return f.res, f.err
}

// librarySet is the set digest a campaign of these library campaigns declares.
func librarySet(t *testing.T, scenarios ...string) string {
	t.Helper()
	var set []domain.Declared
	for _, id := range scenarios {
		e, ok := library.Campaign(id)
		if !ok {
			t.Fatalf("no library campaign %s", id)
		}
		set = append(set, domain.Declared{ID: id, Digest: e.Digest})
	}
	return domain.SetDigest(set)
}

func result(id ids.UUID, set string) cports.Result {
	return cports.Result{
		Campaign: domain.Campaign{ID: id, SetDigest: set, Scenarios: []string{"RT-140", "RT-148"}},
		Steps: []domain.Step{
			{Scenario: "RT-140", Outcome: domain.Held},
			{Scenario: "RT-148", Outcome: domain.NotRoutedReported},
		},
	}
}

// TestD312_CampaignStepsKeepTheServersOutcomeAndLibraryTags: outcomes pass
// through as the server derived them, tags come from the campaign library
// (D529), and a truncated read stays truncated.
// Covers: F893
func TestD312_CampaignStepsKeepTheServersOutcomeAndLibraryTags(t *testing.T) {
	id := ids.NewV7()
	f := &fake{res: cports.Results{Truncated: true, Items: []cports.Result{result(id, librarySet(t, "RT-140", "RT-148"))}}}
	start, end := time.Unix(1, 0), time.Unix(2, 0)
	steps, truncated, err := campaignresults.Library(f).CampaignSteps(context.Background(), ids.OrgID{}, start, end)
	if err != nil || !truncated || len(steps) != 2 {
		t.Fatalf("%+v %v %v", steps, truncated, err)
	}
	if !f.got.Start.Equal(start) || !f.got.End.Equal(end) || f.got.Agent != nil {
		t.Errorf("filter: %+v", f.got)
	}
	if s := steps[0]; s.Campaign != id || s.Outcome != ports.OutcomeHeld || !slices.Equal(s.Tags, library.CampaignASI("RT-140")) || len(s.Tags) == 0 {
		t.Errorf("RT-140: %+v", s)
	}
	if s := steps[1]; s.Outcome != ports.OutcomeNotRoutedReported || !slices.Equal(s.Tags, library.CampaignASI("RT-148")) {
		t.Errorf("RT-148: %+v", s)
	}
	boom := errors.New("boom")
	if _, _, err := campaignresults.Library(&fake{err: boom}).CampaignSteps(context.Background(), ids.OrgID{}, start, end); !errors.Is(err, boom) {
		t.Errorf("err: %v", err)
	}
}

// TestT260_ACampaignNotOfTheLibraryCountsForNoControl: a campaign whose set
// digest is not the library's keeps its outcomes but carries no tag (D531 L2).
// Covers: F893
func TestT260_ACampaignNotOfTheLibraryCountsForNoControl(t *testing.T) {
	for name, set := range map[string]string{
		"another set digest": "0000000000000000000000000000000000000000000000000000000000000000",
		"a set of one":       librarySet(t, "RT-140"),
		"no set":             "",
	} {
		f := &fake{res: cports.Results{Items: []cports.Result{result(ids.NewV7(), set)}}}
		steps, _, err := campaignresults.Library(f).CampaignSteps(context.Background(), ids.OrgID{}, time.Unix(1, 0), time.Unix(2, 0))
		if err != nil || len(steps) != 2 {
			t.Fatalf("%s: %+v %v", name, steps, err)
		}
		for _, s := range steps {
			if len(s.Tags) != 0 {
				t.Errorf("%s: a step carries %v", name, s.Tags)
			}
		}
		if steps[0].Outcome != ports.OutcomeHeld {
			t.Errorf("%s: outcome %s", name, steps[0].Outcome)
		}
	}
	// A scenario the campaign library does not hold makes the set unknown.
	r := result(ids.NewV7(), librarySet(t, "RT-140", "RT-148"))
	r.Campaign.Scenarios = append(r.Campaign.Scenarios, "RT-999")
	steps, _, err := campaignresults.Library(&fake{res: cports.Results{Items: []cports.Result{r}}}).CampaignSteps(context.Background(), ids.OrgID{}, time.Unix(1, 0), time.Unix(2, 0))
	if err != nil || len(steps[0].Tags) != 0 {
		t.Errorf("an unknown scenario in the set: %+v %v", steps, err)
	}
}
