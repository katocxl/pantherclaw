// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "publisher.". The ledger stores each as "audit." + the kind.
const (
	PublisherClearRequested = "publisher.clear_requested"
	PublisherCleared = "publisher.cleared"
	PublisherCompromised = "publisher.compromised"
	PublisherExposureReviewed = "publisher.exposure_reviewed"
)
