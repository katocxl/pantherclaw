// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M28 threat map permission (G0 M28 D722, HR-686).
//
//   - threatmap.read: read the org's MITRE ATT&CK and ATLAS threat map, its
//     technique pages, gaps, exports and history. The roles that read
//     compliance coverage or detections hold it: Org Admin, Security Admin,
//     Responder and Auditor.
const PermThreatMapRead Permission = "threatmap.read"

// m28Catalog are the M28 permissions in catalog order.
var m28Catalog = []Permission{PermThreatMapRead}
