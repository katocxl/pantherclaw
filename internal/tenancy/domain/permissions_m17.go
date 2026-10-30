// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M17 permissions (G0 M17 D107). consequence_rule.manage proposes and
// retires the org's customer consequence rules, each a protected change a
// second person holding it confirms (HR-453). Retiring a rule takes away
// requirements, so it is human only.
const PermConsequenceRuleManage Permission = "consequence_rule.manage"

// m17Catalog are the M17 permissions in catalog order.
var m17Catalog = []Permission{PermConsequenceRuleManage}
