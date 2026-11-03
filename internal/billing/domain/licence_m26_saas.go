// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// SaaSDiscovery reports whether the edition finds agents people built in SaaS
// tenants (G0 M26 D407): Business and above.
func (e Entitlements) SaaSDiscovery() bool { return e.businessPlus() }
