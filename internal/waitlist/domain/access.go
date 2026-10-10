// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Access requests (decision 10, F051): the run's launcher or represented
// principal may file one for the run's grant, and so may the workload when
// it cites one of its own run's denials about scope, at most 3 per run.
// The note is UNTRUSTED. A request grants nothing.
const (
	MaxWorkloadAccessRequests = 3
	// MaxAccessNote caps an access request's note, in bytes.
	MaxAccessNote = 4096
)

// scopeReasons are the decisive reasons of a denial that a revision of the
// run's grant could change. A guardrail, a budget or a missing grant is not
// the grant's scope.
var scopeReasons = []string{
	gdomain.ReasonOperationNotGranted, gdomain.ReasonTargetNotGranted, gdomain.ReasonDestinationNotGranted,
	gdomain.ReasonGrantLimitExceeded, gdomain.ReasonOutsideTimeWindow,
}

// ScopeDenial reports whether a transaction's decision and decisive reason
// are a denial about the grant's scope, which a workload may cite.
func ScopeDenial(decision, reason string) bool {
	return decision == "DENY" && slices.Contains(scopeReasons, reason)
}
