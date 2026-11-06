// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of browser agents (G0 M33 D976, D978, D986), kept in one
// file: "browser." and the gateway's local refusal of a secret-field
// submit. The ledger stores each as "audit." + the kind.
const (
	BrowserCloakingSuspected = "browser.cloaking_suspected"
	BrowserSiteAdded         = "browser.site_added"
	BrowserSiteRemoved       = "browser.site_removed"
	// ConnectionBrowserSecretFieldRefused: a pc.browser form submit with a
	// password, one-time-code or payment field was refused at the gateway
	// before the Authority was asked (D978, HR-747).
	ConnectionBrowserSecretFieldRefused = "connection.browser_secret_field_refused"
)
