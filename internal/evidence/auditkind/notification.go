// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "notification.". The ledger stores each as "audit." + the kind.
const (
	NotificationChannelCreated = "notification.channel_created"
	NotificationChannelDeleted = "notification.channel_deleted"
	NotificationChannelPaused = "notification.channel_paused"
	NotificationChannelSecretRotated = "notification.channel_secret_rotated"
	NotificationChannelSignatureSchemeSet = "notification.channel_signature_scheme_set"
	NotificationChannelTested = "notification.channel_tested"
	NotificationChannelUpdated = "notification.channel_updated"
	NotificationChatLinkConfirmed = "notification.chat_link_confirmed"
	NotificationChatLinkProposed = "notification.chat_link_proposed"
	NotificationChatLinkRevoked = "notification.chat_link_revoked"
	NotificationChatLinkStale = "notification.chat_link_stale"
	NotificationSlackAppActivated = "notification.slack_app_activated"
	NotificationSlackCardOrphaned = "notification.slack_card_orphaned"
	NotificationSlackChannelShared = "notification.slack_channel_shared"
	NotificationSlackTokenReplaced = "notification.slack_token_replaced"
	NotificationTeamsAppActivated = "notification.teams_app_activated"
	NotificationTeamsAppRefusedShared = "notification.teams_app_refused_shared"
	NotificationTeamsChannelShared = "notification.teams_channel_shared"
)
