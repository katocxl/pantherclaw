// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "redteam.". The ledger stores each as "audit." + the kind.
const (
	RedteamCampaignAbandoned = "redteam.campaign_abandoned"
	RedteamCampaignFinished = "redteam.campaign_finished"
	RedteamCampaignStarted = "redteam.campaign_started"
	RedteamCampaignStepStarted = "redteam.campaign_step_started"
	RedteamRangeAbandoned = "redteam.range_abandoned"
	RedteamRangeFinished = "redteam.range_finished"
	RedteamRangeStarted = "redteam.range_started"
	RedteamResultRecorded = "redteam.result_recorded"
)
