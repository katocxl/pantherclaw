// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "github.". The ledger stores each as "audit." + the kind.
const (
	GithubAccountExempted     = "github.account_exempted"
	GithubExemptionRemoved    = "github.exemption_removed"
	GithubIdentityLinkRefused = "github.identity_link_refused"
	GithubIdentityLinked      = "github.identity_linked"
	GithubIdentityUnlinked    = "github.identity_unlinked"
	GithubScanFinished        = "github.scan_finished"
	GithubScanStarted         = "github.scan_started"
)
