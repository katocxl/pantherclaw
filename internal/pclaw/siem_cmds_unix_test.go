// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build unix

package pclaw

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// TestHR662_ForwarderStopsGracefullyOnSIGTERM: the SIGTERM a service
// manager sends stops the forwarder the graceful way, as an interrupt
// does: it logs that it is stopping, drains and exits 0.
// Covers: F950
func TestHR662_ForwarderStopsGracefullyOnSIGTERM(t *testing.T) {
	_, _, stderr, stop := startForward(t, map[string]string{envSIEMSecret: ndomain.FormatSecret(fwdSecret)}, "--out", "-")
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(stderr.String(), `"event":"siem.forward.stopping"`) {
		if time.Now().After(deadline) {
			t.Fatalf("SIGTERM did not stop the forwarder: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c := stop(); c != 0 {
		t.Errorf("exit %d: %s", c, stderr.String())
	}
}
