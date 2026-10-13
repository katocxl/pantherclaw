// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// Codes that refuse a GitHub App connection's action before anything is
// asked or minted (ADR-0021): a repository of another account than the
// connection's installation, or a connection whose installation is not
// recorded, so the account it may act on is unknown.
const (
	CodeWrongAccount        = "WRONG_ACCOUNT"
	CodeInstallationUnknown = "INSTALLATION_UNKNOWN"
)

// errInstallation refuses a GitHub App credential sealed for another
// installation, App or account than the connection records, or for a
// connection that records none.
var errInstallation = errors.New("dispatch: the sealed GitHub App is not the connection's installation")

// accountRefusal is the code refusing a GitHub App connection's action
// before the decision: INSTALLATION_UNKNOWN without a recorded
// installation, WRONG_ACCOUNT for a repository whose owner is not the
// installation's account; "" otherwise.
func accountRefusal(conn *control.Connection, a actionir.ActionIR) string {
	if conn.Credential.GetKind() != credentials.KindGitHubApp || conn.Package == nil {
		return ""
	}
	gh := conn.GetGithub()
	if gh == nil {
		return CodeInstallationUnknown
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok {
		return ""
	}
	if owner, ok := def.Target.Part(a.Target.ID, "owner"); ok && owner != gh.GetAccountLogin() {
		return CodeWrongAccount
	}
	return ""
}

// installed reports whether a sealed GitHub App credential is for the
// connection's recorded installation (never, when none is recorded).
func installed(conn *control.Connection, app credentials.GitHubApp) bool {
	gh := conn.GetGithub()
	return gh != nil && credentials.Installation{AppClientID: gh.GetAppClientId(), ID: gh.GetInstallationId(), Account: gh.GetAccountLogin()}.Matches(app)
}
