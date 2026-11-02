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

func tags(s string) []string {
	if s == "RT-001" {
		return []string{"ASI02"}
	}
	return nil
}

// TestD312_CampaignStepsKeepTheServersOutcomeAndLibraryTags: outcomes pass
// through as the server derived them, a tag comes only from the library, and
// a truncated read stays truncated.
// Covers: F893
func TestD312_CampaignStepsKeepTheServersOutcomeAndLibraryTags(t *testing.T) {
	id := ids.NewV7()
	f := &fake{res: cports.Results{Truncated: true, Items: []cports.Result{{
		Campaign: domain.Campaign{ID: id},
		Steps: []domain.Step{
			{Scenario: "RT-001", Outcome: domain.Held},
			{Scenario: "RT-999", Outcome: domain.NotRoutedReported},
		},
	}}}}
	start, end := time.Unix(1, 0), time.Unix(2, 0)
	steps, truncated, err := campaignresults.Reader{Results: f, Tags: tags}.CampaignSteps(context.Background(), ids.OrgID{}, start, end)
	if err != nil || !truncated || len(steps) != 2 {
		t.Fatalf("%+v %v %v", steps, truncated, err)
	}
	if !f.got.Start.Equal(start) || !f.got.End.Equal(end) || f.got.Agent != nil {
		t.Errorf("filter: %+v", f.got)
	}
	if s := steps[0]; s.Campaign != id || s.Outcome != ports.OutcomeHeld || !slices.Equal(s.Tags, []string{"ASI02"}) {
		t.Errorf("step: %+v", s)
	}
	if s := steps[1]; len(s.Tags) != 0 || s.Outcome != ports.OutcomeNotRoutedReported {
		t.Errorf("unknown scenario: %+v", s)
	}
	boom := errors.New("boom")
	if _, _, err := (campaignresults.Reader{Results: &fake{err: boom}, Tags: tags}).CampaignSteps(context.Background(), ids.OrgID{}, start, end); !errors.Is(err, boom) {
		t.Errorf("err: %v", err)
	}
}
