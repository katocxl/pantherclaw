// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "incident.". The ledger stores each as "audit." + the kind.
const (
	IncidentAlertLinked        = "incident.alert_linked"
	IncidentAlertPromoted      = "incident.alert_promoted"
	IncidentAlertStateSet      = "incident.alert_state_set"
	IncidentAssigned           = "incident.assigned"
	IncidentFailureAssigned    = "incident.failure_assigned"
	IncidentFailureResolved    = "incident.failure_resolved"
	IncidentStateSet           = "incident.state_set"
	IncidentSuppressionCreated = "incident.suppression_created"
	IncidentSuppressionEnded   = "incident.suppression_ended"
)
