// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m14SlackTemplates are the Slack approval channel notices (G0 M14 D88):
// fixed text and the channel's name only (HR-158).
var m14SlackTemplates = []Template{
	{
		Type: "notification.slack_channel_shared", Severity: Warning, Params: []string{"channel"},
		Title: "A Slack approval channel was paused: it is shared outside the workspace",
		Body: "Slack now reports the channel of the notification channel {channel} as shared with another workspace or " +
			"organization, so PantherClaw stopped posting approval cards there. It waits for an Org Admin to check and " +
			"activate it again on its page, or to delete it.",
	},
}

func init() { templates = append(templates, m14SlackTemplates...) }
