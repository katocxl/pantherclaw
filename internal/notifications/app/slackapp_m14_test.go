// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// TestM14_SlackAppChannelsFailClosed: a slack_app channel is defined but
// not yet delivered, so creating one is refused before anything is stored;
// its configuration belongs to it alone (G0 M14 D4).
func TestM14_SlackAppChannelsFailClosed(t *testing.T) {
	var s app.Service
	cfg := &domain.SlackAppConfig{ChannelID: "C0123456789", DataLevel: domain.SlackMinimal, BotToken: "xoxb-test"}
	for name, c := range map[string]struct {
		in   app.ChannelInput
		want error
	}{
		"slack_app":             {app.ChannelInput{Name: "approvals", Kind: domain.KindSlackApp, SlackApp: cfg}, app.ErrKindNotImplemented},
		"slack_app, no config":  {app.ChannelInput{Name: "approvals", Kind: domain.KindSlackApp}, app.ErrInvalidChannel},
		"webhook, slack config": {app.ChannelInput{Name: "hook", Kind: domain.KindWebhook, SlackApp: cfg}, app.ErrInvalidChannel},
	} {
		if _, _, err := s.CreateChannel(context.Background(), c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !domain.KindSlackApp.Valid() || !domain.KindSlackApp.HasSecret() {
		t.Fatal("slack_app kind")
	}
}
