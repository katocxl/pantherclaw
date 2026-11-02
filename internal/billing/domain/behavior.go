// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// BehaviorAnalytics reports the behavior profiles, their inferred alerts and
// approval context (Business and Enterprise; G0 M27 D502, H3).
func (e Entitlements) BehaviorAnalytics() bool { return e.businessPlus() }
