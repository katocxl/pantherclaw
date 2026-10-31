// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// OutcomeMetrics reports whether the edition includes the outcome metrics
// (G0 M21 D303, F774): Business and Enterprise.
func (e Entitlements) OutcomeMetrics() bool { return e.businessPlus() }
