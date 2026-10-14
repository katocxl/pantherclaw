// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "time"

// Exception is an active policy exception as the Authority reads it in a
// decision's snapshot (G0 M11.1 D14, HR-235): it waives rule Rule, as it
// was when the exception was requested (RuleDigest, hex), for the agent the
// decision is about and the listed exact operations, until ExpiresAt by
// the database clock.
type Exception struct {
	ID         string    `json:"id"`
	Rule       string    `json:"rule"`
	RuleDigest string    `json:"rule_digest"`
	Operations []string  `json:"operations"`
	ExpiresAt  time.Time `json:"expires_at"`
}
