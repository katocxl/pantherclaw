// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "idaccess.". The ledger stores each as "audit." + the kind.
const (
	IdaccessClientDocumentChanged = "idaccess.client_document_changed"
	IdaccessClientRemoved = "idaccess.client_removed"
	IdaccessCodeReuse = "idaccess.code_reuse"
	IdaccessConsentGiven = "idaccess.consent_given"
	IdaccessIssuerDisabled = "idaccess.issuer_disabled"
	IdaccessLapsed = "idaccess.lapsed"
	IdaccessMcpAccessDisabled = "idaccess.mcp_access_disabled"
	IdaccessMcpClientRemoved = "idaccess.mcp_client_removed"
	IdaccessRefreshReuse = "idaccess.refresh_reuse"
	IdaccessTokenIssued = "idaccess.token_issued"
)
