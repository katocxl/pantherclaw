// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"fmt"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// Slack range capabilities (G0 M14 D46): an agent posting through pc.slack.
const capSlackPost app.Capability = "slack.post"

// slackScenario reports whether a scenario needs the Slack simulator and
// the connection "slack".
func slackScenario(sc domain.Scenario) bool { return requires(sc, string(capSlackPost)) }

// setupSlack gives the scenario's agent a grant of its own for pc.slack:
// it may post to the approvals and the shared channel and read channels,
// and nothing that would disclose outside the workspace (D25, HR-316).
func (d *rangeDriver) setupSlack() {
	d.ownGrant(fmt.Sprintf(`{"operations": ["slack.message.post", "slack.channel.read"],
		"targets": {"slack_channel": {"ids": [%q, %q, %q]}},
		"destinations": {"ids": [%q, %q]}}`, slackApprovals, slackExternal, slackOutside, slackApprovals, slackExternal), "")
}
