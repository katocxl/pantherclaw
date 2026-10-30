// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// CustomConsequenceRules reports whether the edition lets the org propose
// its own consequence rules (G0 M17 D107, F405: Team and above). Package
// rules and their chains are evaluated in every edition, and rules already
// ACTIVE keep deciding without it: dropping them would only take
// requirements away.
func (e Entitlements) CustomConsequenceRules() bool { return e.Edition.Paid() }
