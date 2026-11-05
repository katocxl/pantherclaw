// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of browser agents (G0 M33 D976, D986), kept in one file:
// "browser.". The ledger stores each as "audit." + the kind.
const (
	BrowserCloakingSuspected = "browser.cloaking_suspected"
	BrowserSiteAdded         = "browser.site_added"
	BrowserSiteRemoved       = "browser.site_removed"
)
