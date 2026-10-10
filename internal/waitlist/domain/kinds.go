// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"time"

	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Entry states.
const (
	StateOpen     = "OPEN"
	StateApproved = "APPROVED"
	StateRejected = "REJECTED"
	StateExpired  = "EXPIRED"
)

// DefaultDeadlines is how long an entry of each kind waits (design
// decision 6): an org's settings may only shorten them. A hold's deadline
// is its approval request's.
var DefaultDeadlines = map[string]time.Duration{
	KindAdmission:      7 * 24 * time.Hour,
	KindAccessRequest:  7 * 24 * time.Hour,
	KindToolReview:     30 * 24 * time.Hour,
	KindRestoration:    24 * time.Hour,
	KindReconciliation: 72 * time.Hour,
}

// Deadline is the wait of kind: the org's setting when it has one, which
// the schema keeps within the decision-6 bounds, else the default.
func Deadline(kind string, configuredSeconds *int32) time.Duration {
	if configuredSeconds != nil && *configuredSeconds > 0 {
		if d := time.Duration(*configuredSeconds) * time.Second; d < DefaultDeadlines[kind] {
			return d
		}
	}
	return DefaultDeadlines[kind]
}

// Expires reports whether an open entry of kind ends as EXPIRED at its
// deadline, so nothing changes (HR-177). A RECONCILIATION entry never
// resolves by itself: an unknown outcome stays visible and escalates until
// M7 resolves it (HR-003, design decision 20). Holds and restorations end
// with their approval request; admissions with M3's rules.
func Expires(kind string) bool {
	return kind == KindAccessRequest || kind == KindToolReview
}

// DeciderPermission is the permission whose holders decide an entry of kind
// on its agent's scope path (the org's, for a tool review), and so may
// assign it to themselves. Holds and restorations are decided under the
// approval rules instead (HR-170). A RECONCILIATION entry is resolved in
// M7; until then its deciders are the holders of incident.respond.
func DeciderPermission(kind string) (td.Permission, bool) {
	switch kind {
	case KindAdmission:
		return td.PermAgentAdmit, true
	case KindAccessRequest:
		return td.PermGrantIssue, true
	case KindToolReview:
		return td.PermPackageActivate, true
	case KindReconciliation:
		return td.PermIncidentRespond, true
	}
	return "", false
}
