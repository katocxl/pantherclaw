// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package notificationsrpc

import (
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// TestM14_SlackAppDataLevelDefaultsMinimal: a slack_app configuration
// without a data level, or with one this build does not know, shows the
// minimal card; only SUMMARY asks for more. The team id is never taken
// from the caller (G0 M14 D56).
func TestM14_SlackAppDataLevelDefaultsMinimal(t *testing.T) {
	for level, want := range map[pantherclawv1.SlackDataLevel]string{
		pantherclawv1.SlackDataLevel_SLACK_DATA_LEVEL_UNSPECIFIED: domain.SlackMinimal,
		pantherclawv1.SlackDataLevel_SLACK_DATA_LEVEL_MINIMAL:     domain.SlackMinimal,
		pantherclawv1.SlackDataLevel(99):                          domain.SlackMinimal,
		pantherclawv1.SlackDataLevel_SLACK_DATA_LEVEL_SUMMARY:     domain.SlackSummary,
	} {
		got := slackAppIn(&pantherclawv1.SlackAppConfig{ChannelId: "C0123456789", DataLevel: level, TeamId: "T0CALLER"})
		if got.DataLevel != want || got.TeamID != "" || got.ChannelID != "C0123456789" {
			t.Errorf("%v: %+v", level, got)
		}
	}
	if slackAppIn(nil) != nil {
		t.Error("no configuration became one")
	}
}
