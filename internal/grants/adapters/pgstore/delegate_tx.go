// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgstore

import "github.com/katocxl/pantherclaw/internal/grants/app"

// The store delegates in a caller's transaction too (G0 M14 D89).
var _ app.DelegateTxStore = (*Store)(nil)
