// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// ErrMaintenanceHold refuses every decision while the operator's
// maintenance hold is on (G0 M13 D26, HR-379). It is UNAVAILABLE, so
// gateways fail closed and retry once the hold is lifted.
var ErrMaintenanceHold = pcerr.New(pcerr.Unavailable, "MAINTENANCE_HOLD",
	"the server is in an operator maintenance hold; no decision is made")

// WithMaintenanceHold makes every decision entry point — Authorize, Decide,
// BeginDispatch, Verify and ObserveTool — refuse with ErrMaintenanceHold
// while on, whichever path calls it (HR-379).
func (s *Service) WithMaintenanceHold(on bool) *Service {
	s.held = on
	return s
}

// Held reports whether the maintenance hold is on.
func (s *Service) Held() bool { return s.held }
