// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"strconv"
)

// processIdentity returns when process pid started, which tells it from a
// later process given the same id (D134). /proc needs no ps, and BusyBox's
// ps has no lstart (D146).
func processIdentity(_ context.Context, pid int) (string, error) {
	return readProcStart("/proc/" + strconv.Itoa(pid) + "/stat")
}
