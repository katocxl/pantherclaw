// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Witnesses reports whether public witnesses may cosign the deployment-wide
// root log (G0 M35 D1041): Business and Enterprise.
func (e Entitlements) Witnesses() bool { return e.businessPlus() }
