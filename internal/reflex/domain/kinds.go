// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "strings"

// Ledger kinds of the M10 streams (D6). Bodies are canonical JSON of at
// most MaxLedgerBody bytes with ids and subjects only, never payloads.
const (
	KindAlert          = "reflex.alert"
	KindLive           = "reflex.live"
	KindIncident       = "reflex.incident"
	KindCase           = "reflex.case"
	KindResponseAction = "response.action"
	KindResponsePath   = "response.path"
	KindPostureFinding = "posture.finding"

	// MaxLedgerBody bounds a Reflex ledger body.
	MaxLedgerBody = 8 << 10
)

// ReflexKind reports whether a ledger kind is Reflex's own output, which
// detection never reads back (no feedback loops, D2).
func ReflexKind(kind string) bool { return strings.HasPrefix(kind, "reflex.") }

// Notification types (D7). Each stream adds its own templates file.
const (
	NotifyAlert    = "reflex.alert"
	NotifyIncident = "reflex.incident"
	NotifyPage     = "reflex.page"
	NotifyDigest   = "reflex.digest"

	NotifyContainmentPartial = "response.containment_partial"
	NotifyContainmentFailed  = "response.containment_failed"
	NotifyRestorationReady   = "response.restoration_ready"

	NotifySIEMDeliveryFailing = "siem.delivery_failing"
	NotifySignalsReceived     = "signals.event_received"
	NotifyPlaybookChanged     = "signals.playbook_changed"
)
