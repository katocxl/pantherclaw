// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of publisher pins and bundles (G0 M37 D1081–D1083;
// HR-795..800): a pin created PENDING, activated with a security key and
// revoked; a bundle installed as drafts or refused; an install revoked.
// The ledger stores each as "audit." + the kind.
const (
	BundleInstallFailed      = "bundle.install_failed"
	BundleInstalled          = "bundle.installed"
	BundleRevoked            = "bundle.revoked"
	PublisherPinActivated    = "publisher.pin_activated"
	PublisherPinCreated      = "publisher.pin_created"
	PublisherPinRevoked      = "publisher.pin_revoked"
)
