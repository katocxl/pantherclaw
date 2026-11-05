// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// PartnerAccess reports whether the org may act as an MSSP partner: ask
// customers for partner links, open partner sessions, read the
// cross-customer summary and propose rollouts (G0 M38 D1100): Enterprise.
// It is checked on the partner org only; the customer org needs none.
func (e Entitlements) PartnerAccess() bool { return e.Edition == Enterprise }
