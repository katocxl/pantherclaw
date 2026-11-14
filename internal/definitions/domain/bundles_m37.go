// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"

// ExtensionPrefix starts the name of a package a publisher bundle drafted
// (G0 M37 D1082b).
const ExtensionPrefix = "ext."

// ErrBundleItemMismatch refuses importing an ext.* package without a
// DRAFTED bundle item of the same name@version and the same package.yaml
// bytes in the org (D1082b, HR-796).
var ErrBundleItemMismatch = pcerr.New(pcerr.FailedPrecondition, "BUNDLE_ITEM_MISMATCH",
	"an ext. package is imported only as drafted by an installed bundle, with the same name, version and bytes")
