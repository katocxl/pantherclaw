// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// KindSlackApp is a Slack bot posting approval cards to one channel and
// updating them in place (G0 M14 D22, Team edition). Its bot token is the
// channel's encrypted secret, like a Slack webhook URL.
const KindSlackApp Kind = "slack_app"

// Slack card data levels (G0 M14 D23).
const (
	SlackMinimal = "MINIMAL"
	SlackSummary = "SUMMARY"
)

// SlackAppConfig is a slack_app channel's configuration. BotToken is
// input only: it is encrypted and never returned; TeamID comes from
// auth.test, never from the caller.
type SlackAppConfig struct {
	ChannelID string
	DataLevel string
	TeamID    string
	BotToken  string
	// DirectMessages: the bot also sends approval DMs (G0 M20 D256); set
	// at creation only.
	DirectMessages bool
}
