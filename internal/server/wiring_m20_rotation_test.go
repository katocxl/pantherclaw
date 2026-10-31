// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// Covers: F424
// TestT224_NoJobClientFailsTheRotationChange: a rotation cannot commit
// without its recompute. When the job client cannot be built, the change
// fails, and the hook does not try to build it again.
func TestT224_NoJobClientFailsTheRotationChange(t *testing.T) {
	boom := errors.New("no job queue")
	builds := 0
	prev := insertJobClient
	insertJobClient = func(*db.Pool, *slog.Logger) (*jobs.Client, error) {
		builds++
		return nil, boom
	}
	t.Cleanup(func() { insertJobClient = prev })
	changed := rotationRecompute(nil, nil)
	if builds != 0 {
		t.Fatalf("wiring built the job client %d times, want none before a change", builds)
	}
	for range 2 {
		if err := changed(context.Background(), db.TenantTx{}); !errors.Is(err, boom) {
			t.Fatalf("change: %v, want the job client's error", err)
		}
	}
	if builds != 1 {
		t.Fatalf("built the job client %d times, want once", builds)
	}
}
