// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M16 permissions (G0 M16 D81).
//
//   - policy.external_check.manage: create, activate (on the check's page,
//     with a security-key step-up), disable and test external policy
//     checks (HR-438). Security Admin holds it; it is human only. Listing
//     checks needs policy.read.
const PermExternalCheckManage Permission = "policy.external_check.manage"

// m16Catalog are the M16 permissions in catalog order.
var m16Catalog = []Permission{PermExternalCheckManage}
