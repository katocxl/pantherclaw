// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M25 permissions (G0 M25 D311). compliance.read reads framework coverage;
// Auditor, Org Admin and Security Admin hold it. A report's export needs
// evidence.export, and what a reader may not read stays a gap (D312).
const (
	PermComplianceRead Permission = "compliance.read"
)

// m25Catalog are the M25 permissions in catalog order.
var m25Catalog = []Permission{PermComplianceRead}
