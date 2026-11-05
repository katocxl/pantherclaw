// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the states, reasons and errors of publisher pins,
// bundle installs and revocations (G0 M37 D1081–D1083; HR-795..800). It is
// pure: no I/O. "Publisher" here is always a bundle publisher.
package domain

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/bundles/format"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions (D1081).
const (
	PermPublisherManage = td.PermPublisherManage
	PermBundleInstall   = td.PermBundleInstall
	PermBundleRead      = td.PermBundleRead
)

// Pin states.
const (
	PinPending = "PENDING"
	PinActive  = "ACTIVE"
	PinRevoked = "REVOKED"
)

// Pin revoke reasons.
const (
	ReasonUnpinned         = "UNPINNED"
	ReasonCompromised      = "COMPROMISED"
	ReasonPublisherRevoked = "PUBLISHER_REVOKED"
)

// Install states.
const (
	InstallPending   = "PENDING"
	InstallInstalled = "INSTALLED"
	InstallFailed    = "FAILED"
	InstallRevoked   = "REVOKED"
)

// Item states.
const (
	ItemDrafted  = "DRAFTED"
	ItemTemplate = "TEMPLATE"
	ItemRevoked  = "REVOKED"
)

// Item targets: what an item became.
const (
	TargetPackageDraft = "package_draft"
	TargetCustomRule   = "custom_rule"
	TargetAutomation   = "automation"
	TargetTemplate     = "template"
)

// Revocation sources.
const (
	SourceAdmin     = "ADMIN"
	SourceStatement = "STATEMENT"
	SourceFetch     = "FETCH"
)

// Errors.
var (
	ErrNotFound     = pcerr.New(pcerr.NotFound, "BUNDLE_NOT_FOUND", "not found")
	ErrPinNotFound  = pcerr.New(pcerr.NotFound, "PUBLISHER_PIN_NOT_FOUND", "publisher pin not found")
	ErrPinState     = pcerr.New(pcerr.FailedPrecondition, "PUBLISHER_PIN_STATE", "the pin is not in a state that allows this")
	ErrPinExists    = pcerr.New(pcerr.AlreadyExists, "PUBLISHER_PIN_EXISTS", "this key is already pinned")
	ErrKeyWithdrawn = pcerr.New(pcerr.FailedPrecondition, "PUBLISHER_KEY_WITHDRAWN",
		"this key was revoked as compromised or by its publisher and is never pinned again")
	ErrPinInvalid = pcerr.New(pcerr.InvalidArgument, "PUBLISHER_PIN_INVALID",
		"a pin names a publisher id, a 32-byte Ed25519 key, known item kinds and an optional https revocations URL")
	ErrFingerprint = pcerr.New(pcerr.InvalidArgument, "PUBLISHER_KEY_FINGERPRINT_MISMATCH",
		"the key's SHA-256 fingerprint is not the expected one")
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person signed in as themselves can do this")
	ErrRollback = pcerr.New(pcerr.FailedPrecondition, "ROLLBACK",
		"a later version of this bundle is installed: an older one is refused")
	ErrEquivocation = pcerr.New(pcerr.FailedPrecondition, "EQUIVOCATION",
		"this version of the bundle was installed with different contents")
	ErrBundleRevoked = pcerr.New(pcerr.FailedPrecondition, "BUNDLE_REVOKED",
		"this version of the bundle is revoked: install a later version that is not")
	ErrInstallState = pcerr.New(pcerr.FailedPrecondition, "BUNDLE_INSTALL_STATE", "the install is not INSTALLED")
	ErrReason       = pcerr.New(pcerr.InvalidArgument, "PUBLISHER_PIN_REASON", "the reason must be UNPINNED or COMPROMISED")
)

// FormatError turns a format refusal into an API error with its code: a
// key that is not pinned is a failed precondition, every other refusal an
// invalid argument. Other errors pass unchanged.
func FormatError(err error) error {
	var fe *format.Error
	if !errors.As(err, &fe) {
		return err
	}
	code := pcerr.InvalidArgument
	switch fe.Code {
	case format.ErrUnpinned.Code, format.ErrKindNotPinned.Code, format.ErrExpired.Code:
		code = pcerr.FailedPrecondition
	}
	return pcerr.Wrap(err, code, fe.Code, fe.Msg)
}
