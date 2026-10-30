// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m20TeamsTemplates are the Teams approval channel notices (G0 M20 D256):
// fixed text and the channel's name only (HR-158).
var m20TeamsTemplates = []Template{
	{
		Type: "notification.teams_channel_shared", Severity: Warning, Params: []string{"channel"},
		Title: "A Teams approval channel was paused: it has outside members",
		Body: "The channel of the notification channel {channel} now has a guest or a member of another tenant, so approval " +
			"cards stopped going there. Remove them and activate it again on its page, or delete it.",
	},
}

func init() { templates = append(templates, m20TeamsTemplates...) }
