// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// ModelPromptCapture reports whether the organization may turn prompt
// capture on for a model connection (G0 M30 D945b, founder answer P:
// Business). It gates turning it on only: turning it off works in every
// edition.
func (e Entitlements) ModelPromptCapture() bool { return e.businessPlus() }
