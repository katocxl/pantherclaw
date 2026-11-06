// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M30 range capabilities (D1216). Both are range setup a live range can
// provide, named with `pclaw redteam run --provides`:
//   - share: the range grant names github.repo.visibility.update and
//     github.repo.transfer (RT-201).
//   - agent_config: the range has the agent-configuration hook connection
//     (pc.shell and its hook connection, RT-203).
func init() {
	capabilities = append(capabilities, "share", "agent_config")
	CustomerCapabilities = append(CustomerCapabilities, "share", "agent_config")
}
