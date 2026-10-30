// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import "time"

// SetClock replaces the clock the webhook key caches read (tests only).
func (w *WebhookKeys) SetClock(now func() time.Time) { w.now = now }
