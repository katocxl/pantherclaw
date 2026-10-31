// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M24 permissions (G0 M24 D200, D222, D236). The ranked posture queue reuses
// posture.read; the MCP server catalog and device scans add these.
//
//   - catalog.read: see the org's MCP server catalog and its mode. Org
//     Admin, Security Admin and Auditor hold it.
//   - catalog.manage: propose, approve and deny catalog servers, set the
//     catalog's mode and revoke a server. Only Security Admin holds it. The
//     mode and revoke are for people only with a step-up (HR-586, HR-587),
//     and the catalog service refuses any other caller.
//   - agent.scan.submit: submit a device scan for the holder's scope and
//     nothing else (HR-589). Only the service-only Scanner role holds it.
const (
	PermCatalogRead     Permission = "catalog.read"
	PermCatalogManage   Permission = "catalog.manage"
	PermAgentScanSubmit Permission = "agent.scan.submit"
)

// m24Catalog are the M24 permissions in catalog order.
var m24Catalog = []Permission{PermCatalogRead, PermCatalogManage, PermAgentScanSubmit}
