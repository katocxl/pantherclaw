// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of shared threat-intel indicators (G0 M38 D1103..D1105), kept
// in one file. The ledger stores each as "audit." + the kind. An org's
// matches and contributions are recorded in that org; a feed import is a
// deployment event and is recorded in the operator's log.
const (
	IntelContributed     = "intel.contributed"
	IntelMatched         = "intel.matched"
	IntelSettingsChanged = "intel.settings_changed"
)
