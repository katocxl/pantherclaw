// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Reflex permissions (G0 M10 D4): detections, alerts and incidents, cases,
// breach radius and posture, operations and search, SIEM export, Shared
// Signals and SOAR requests. The .read permissions are scoped like
// agent.read over the agents a row is about; lists and counts filter by
// them before they aggregate (D8).
//
// Managing detections, export destinations, Shared Signals transmitters,
// cases and incidents changes what the organization sees and how it
// responds, so those are human only. response.request is for SOAR service
// accounts: it asks for narrow containment and never lifts any (HR-251).
const (
	PermDetectionRead   Permission = "detection.read"
	PermDetectionManage Permission = "detection.manage"
	PermIncidentRead    Permission = "incident.read"
	PermIncidentManage  Permission = "incident.manage"
	PermCaseRead        Permission = "case.read"
	PermCaseManage      Permission = "case.manage"
	PermExposureRead    Permission = "exposure.read"
	PermPostureRead     Permission = "posture.read"
	PermPostureManage   Permission = "posture.manage"
	PermOperationsRead  Permission = "operations.read"
	PermSearchRead      Permission = "search.read"
	PermSIEMRead        Permission = "siem.read"
	PermSIEMManage      Permission = "siem.manage"
	PermSignalsRead     Permission = "signals.read"
	PermSignalsManage   Permission = "signals.manage"
	PermResponseRequest Permission = "response.request"
)

// reflexCatalog are the Reflex permissions in catalog order.
var reflexCatalog = []Permission{
	PermDetectionRead, PermDetectionManage,
	PermIncidentRead, PermIncidentManage,
	PermCaseRead, PermCaseManage,
	PermExposureRead, PermPostureRead, PermPostureManage,
	PermOperationsRead, PermSearchRead,
	PermSIEMRead, PermSIEMManage, PermSignalsRead, PermSignalsManage,
	PermResponseRequest,
}

// reflexHumanOnly are the Reflex permissions only a person may hold.
var reflexHumanOnly = []Permission{
	PermDetectionManage, PermSIEMManage, PermSignalsManage, PermCaseManage, PermIncidentManage,
}

// reflexReads are every Reflex read permission.
var reflexReads = []Permission{
	PermDetectionRead, PermIncidentRead, PermCaseRead, PermExposureRead, PermPostureRead,
	PermOperationsRead, PermSearchRead, PermSIEMRead, PermSignalsRead,
}

// reflexManage are the Reflex permissions Security Admin holds beyond the
// reads: everything but response.request (D4).
var reflexManage = []Permission{
	PermDetectionManage, PermIncidentManage, PermCaseManage, PermPostureManage, PermSIEMManage, PermSignalsManage,
}
