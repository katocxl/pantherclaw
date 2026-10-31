// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Approval channels (G0 M20 D256; HR-529).
const (
	// KindSlackDM is a direct message to one eligible decider, sent with the
	// bot token of the org's slack_app channel that allows DMs. It is a
	// delivery kind only: no channel has it.
	KindSlackDM Kind = "slack_dm"
	// KindTeamsApp is a Teams bot posting link-only approval cards to one
	// Teams channel (Team edition).
	KindTeamsApp Kind = "teams_app"
)

// DMEvent reports whether a notification type posts an approval DM to
// the deciders it names: a new request, or one escalated to new
// deciders. Reminders, decisions and everything else post none.
func DMEvent(notificationType string) bool {
	switch CardEventOf(notificationType) {
	case CardPost, CardEscalate:
		return true
	case CardClose, CardTest, CardNone:
	}
	return false
}
