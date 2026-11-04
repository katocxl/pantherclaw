// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "authn.". The ledger stores each as "audit." + the kind.
//
//nolint:gosec // G101: audit kind names, not credentials
const (
	AuthnLogin              = "authn.login"
	AuthnSessionCreated     = "authn.session_created"
	AuthnSessionEnded       = "authn.session_ended"
	AuthnSessionReuse       = "authn.session_reuse"
	AuthnSessionRevoked     = "authn.session_revoked"
	AuthnSessionsRevoked    = "authn.sessions_revoked"
	AuthnStepUp             = "authn.step_up"
	AuthnTokenIssued        = "authn.token_issued"
	AuthnWebauthnRegistered = "authn.webauthn_registered"
	AuthnWebauthnRemoved    = "authn.webauthn_removed"
	AuthnWebauthnRenamed    = "authn.webauthn_renamed"
	AuthnWebauthnSuspended  = "authn.webauthn_suspended"
)
