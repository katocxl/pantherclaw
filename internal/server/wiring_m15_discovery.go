// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// registerM15DiscoveryJobs registers connection_inventory.reconcile (G0
// M15 D22): NEW inventory items checked again when a package version
// becomes active or a pin moves.
func registerM15DiscoveryJobs(reg *jobs.Registry, connections *capp.Service) error {
	return jobs.Register(reg, capp.NewInventoryReconcileWorker(connections))
}
