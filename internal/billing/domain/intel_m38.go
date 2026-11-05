// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// IntelConsume reports whether the org may consume shared threat-intel
// indicators (G0 M38 D1103, vision N27): Business and above. Contributing
// works on every edition.
func (e Entitlements) IntelConsume() bool { return e.businessPlus() }
