// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// CodeWrongAccount refuses an action on a repository of another account
// than the connection's GitHub App installation, before anything is asked
// or minted (ADR-0021).
const CodeWrongAccount = "WRONG_ACCOUNT"

// errInstallation refuses a GitHub App credential sealed for another
// installation, App or account than the connection records.
var errInstallation = errors.New("dispatch: the sealed GitHub App is not the connection's installation")

// wrongAccount reports whether a GitHub App connection's action targets a
// repository whose owner is not the installation's account. A connection
// without a recorded installation is left to the mint, which refuses
// another account too.
func wrongAccount(conn *control.Connection, a actionir.ActionIR) bool {
	gh := conn.GetGithub()
	if gh == nil || conn.Credential.GetKind() != credentials.KindGitHubApp || conn.Package == nil {
		return false
	}
	def, ok := conn.Package.Definition(a.Operation)
	if !ok {
		return false
	}
	owner, ok := def.Target.Part(a.Target.ID, "owner")
	return ok && owner != gh.GetAccountLogin()
}

// installed reports whether a sealed GitHub App credential is for the
// connection's recorded installation (always, when none is recorded).
func installed(conn *control.Connection, app credentials.GitHubApp) bool {
	gh := conn.GetGithub()
	return gh == nil || credentials.Installation{AppClientID: gh.GetAppClientId(), ID: gh.GetInstallationId(), Account: gh.GetAccountLogin()}.Matches(app)
}
