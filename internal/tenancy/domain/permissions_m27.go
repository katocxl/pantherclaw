// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// M27 permissions.
//
//   - behavior.read: read an agent's behavior profile and what stands out
//     about a held action (G0 M27 D501, D502). Every role that reads
//     incidents holds it, and so do those who see approval requests, since
//     the context shows beside them. It is scoped: a viewer sees the agents
//     in their scope.
const PermBehaviorRead Permission = "behavior.read"

// m27Catalog are the M27 permissions in catalog order.
var m27Catalog = []Permission{PermBehaviorRead}
