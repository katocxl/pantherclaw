// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Installation is the GitHub App installation behind a connection
// (connection_github; G0 M8 decision 3, ADR-0021): the App, the
// installation and the account it is installed on. It is configuration,
// never a secret, and is stored beside a GitHub App credential so that the
// server and the gateway can refuse an action on another account's
// repository before anything is minted (WRONG_ACCOUNT). It must match what
// was sealed: the gateway refuses a credential whose sealed installation or
// account differs.
type Installation struct {
	AppClientID string
	ID          int64
	Account     string
}

// Validate checks an installation.
func (i Installation) Validate() error {
	if !issuerRe.MatchString(i.AppClientID) || i.ID <= 0 || !accountRe.MatchString(i.Account) {
		return ErrGitHubApp
	}
	return nil
}

// Matches reports whether a sealed GitHub App credential is for this
// installation.
func (i Installation) Matches(app GitHubApp) bool {
	return app.Issuer == i.AppClientID && app.Installation == i.ID && app.Account == i.Account
}
