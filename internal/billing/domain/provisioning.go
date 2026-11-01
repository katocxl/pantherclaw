// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// SCIM reports whether a SCIM directory may add to the org (G0 M26 D406):
// Enterprise. What takes authority away never needs it: a connection a
// licence lapsed under still deprovisions (HR-357's rule for protection).
func (e Entitlements) SCIM() bool { return e.Edition == Enterprise }

// SAML reports whether the org may activate or change a SAML connection
// (G0 M26 D406): Enterprise. Sign-in through an ACTIVE connection works in
// every edition, as for an organization's OpenID providers (G0 M18 D155):
// a lapse must not lock people out.
func (e Entitlements) SAML() bool { return e.Edition == Enterprise }
