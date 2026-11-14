// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of an org's OTLP destinations (G0 M36 D1061; HR-786): created
// PENDING, activated with a security key, tested, and disabled by a person
// or, after 24 hours of failed exports, by the exporter. The ledger stores
// each as "audit." + the kind.
const (
	OtlpDestinationActivated = "otlp.destination_activated"
	OtlpDestinationCreated   = "otlp.destination_created"
	OtlpDestinationDisabled  = "otlp.destination_disabled"
	OtlpDestinationTested    = "otlp.destination_tested"
)
