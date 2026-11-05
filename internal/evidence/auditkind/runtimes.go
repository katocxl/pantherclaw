// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of cloud agent runtimes (G0 M34 D991, D992, D997), kept in one
// file: a connection's runtime target, runtime runs, and daily scan
// schedules. The ledger stores each as "audit." + the kind.
const (
	ConnectionRuntimeTargetCleared = "connection.runtime_target_cleared"
	ConnectionRuntimeTargetSet     = "connection.runtime_target_set"
	RuntimeRunStarted              = "runtime.run_started"
	SaasScanScheduleCleared        = "saas.scan_schedule_cleared"
	SaasScanScheduleSet            = "saas.scan_schedule_set"
)
